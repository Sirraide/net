#ifndef NET_TCP_HH
#define NET_TCP_HH

#include "utils.hh"

#include <arpa/inet.h>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <netdb.h>
#include <thread>

namespace net::tcp {
namespace detail {
/// Data and functions that are common to both client and server.
class tcp_base {
    bool thread_running = false;
    bool stop_receiving = false;
    bool connected = false;
    std::thread recv_thread;
    std::recursive_mutex swap_lock;

protected:
    using error = std::runtime_error;

    int fd = -1;

    /// Get the current error message.
    [[nodiscard]] std::string geterr() const { return std::strerror(errno); }

    /// Raise an error.
    template <typename... arguments>
    [[noreturn]] void raise(fmt::format_string<arguments...> format, arguments&&... args) const {
        std::string message = fmt::format(format, std::forward<arguments>(args)...);
        message += fmt::format(": {}", geterr());
        throw std::runtime_error(message);
    }

public:
    /// Make sure we don't forget to close the socket.
    tcp_base() = default;
    tcp_base(int fd) : fd(fd) {}
    ~tcp_base() { close(); }
    nocopy(tcp_base);
    tcp_base(tcp_base&& other) noexcept : fd(-1) { *this = std::move(other); }
    tcp_base& operator=(tcp_base&& other) noexcept {
        if (this == std::addressof(other)) { return *this; }
        std::scoped_lock lock{swap_lock, other.swap_lock};

        std::swap(fd, other.fd);
        std::swap(thread_running, other.thread_running);
        std::swap(stop_receiving, other.stop_receiving);
        std::swap(connected, other.connected);
        std::swap(recv_thread, other.recv_thread);
        return *this;
    }

    /// Close the socket.
    void close() {
        if (fd != -1) {
            stop_receiving = true;
            ::close(fd);
            fd = -1;
        }
    }

    /// Receive data in a separate thread and call a callback whenever data is received.
    ///
    /// This creates a dedicated thread which repeatedly calls recv(), storing the received
    /// data in a buffer and calling a user-supplied callback when enough data has accumulated.
    /// The thread is joined when it errors, the client is destroyed, or when close()
    /// or stop_receiving() is called.
    ///
    /// \param min_size The minimum number of bytes to receive before calling the callback.
    ///     If the receive buffer contains fewer bytes than this, the callback will not be called.
    ///     If the size is 0, the callback will always be called.
    /// \param callback The callback to call when data is received. It should return the number
    ///     of bytes to remove from the receive buffer.
    /// \param error_callback The callback to call if an error occurs.
    /// \throws std::runtime_error If the receive thread cannot be created.
    template <typename recv_data_type>
    void recv_async(
        size_t min_size,
        std::function<size_t(const recv_data_type&)> callback,
        std::function<void(const std::exception&)> error_callback
    ) {
        if (not connected) throw error("Cannot receive data on a disconnected socket");
        if (thread_running) throw error("SSL client already receiving");
        if (stop_receiving) throw error("SSL client shutting down");
        if (min_size > std::numeric_limits<int>::max()) throw error("SSL client recv size too large");

        /// Set a receive timeout.
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        auto res = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        if (res == -1) raise("setsockopt() failed");

        /// Start receiving asynchronously.
        recv_thread = std::thread([this, callback = std::move(callback), error_callback = std::move(error_callback), min_size] {
            /// Clear the buffer.
            thread_running = true;
            recv_data_type recv_buffer;

            /// If min_size is small, we can avoid reallocations by using a larger buffer.
            size_t reserve = std::max(min_size, size_t(1024));

            /// Receive data.
            while (not stop_receiving) {
                /// Make sure we don't try to move this while we're receiving.

                /// Reserve more space in the buffer.
                auto sz = recv_buffer.size();
                recv_buffer.resize(sz + reserve);

                /// Receive data.
                auto n_read = recv(recv_buffer.data() + sz, reserve, 100'000);
                recv_buffer.resize(sz + n_read);

                /// Call the callback if we have enough data.
                if (n_read < min_size) continue;
                std::unique_lock lock{swap_lock};
                auto processed = callback(recv_buffer);
                lock.unlock();
                recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + processed);
            }
        });
    }

    /// Send a message.
    ///
    /// \param msg The message to send.
    /// \throw std::runtime_error if the call to ::send() fails.
    void send(std::string_view msg) {
        if (not connected) throw error("Cannot send data on a disconnected socket");
        std::unique_lock lock{swap_lock};
        auto n = ::send(fd, msg.data(), msg.size(), 0);
        if (n == -1) raise("send() failed");
    }

    /// Receive data from the server.
    ///
    /// \param data The buffer to receive the data into.
    /// \param size The size of the buffer (in bytes).
    /// \param us_timeout How long to wait between each attempted receive (in microseconds).
    /// \returns The number of bytes received.
    /// \throws std::runtime_error If the receive fails.
    size_t recv(char* data, size_t size, size_t us_interval = 50) {
        if (thread_running and std::this_thread::get_id() != recv_thread.get_id()) throw error("Cannot recv() while receive thread is running");
        if (not size) return 0;

        /// Receive data.
        for (;;) {
            std::unique_lock lock{swap_lock};
            auto n_read = ::recv(fd, data, size, 0);
            lock.unlock();
            if (n_read <= 0) {

                if (errno == EINTR or errno == EAGAIN or errno == EWOULDBLOCK)
                    std::this_thread::sleep_for(std::chrono::microseconds(us_interval));
                else raise("recv() failed");
            } else return n_read;
        }
    }
};
} // namespace detail

/// Connexion to a client.
using connexion = detail::tcp_base;

/// ===========================================================================
///  TCP Server
/// ===========================================================================
struct server : detail::tcp_base {
    server() = default;
    ~server() { close(); }
    nocopy(server);
    server(server&& other) noexcept = default;
    server& operator=(server&& other) noexcept = default;

    /// Listen on a port.
    ///
    /// \param port Port number.
    /// \throw std::runtime_error if there is an error.
    void listen(u16 port, int max_connexions = 128) {
        /// A negative number of connexions is nonsense.
        if (max_connexions < 1) throw error("max_connexions must be >= 1");

        /// Create the socket.
        if (fd != -1) ::close(fd);
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) raise("socket() failed");

        /// Bind to port.
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = ::htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            ::close(fd);
            fd = -1;
            raise("bind() failed");
        }

        /// Listen.
        if (::listen(fd, max_connexions) == -1) {
            ::close(fd);
            fd = -1;
            raise("listen() failed");
        }
    }

    /// Accept a connexion.
    /// \throw std::runtime_error if there is an error.
    [[nodiscard]] connexion accept() const {
        return connexion{::accept(fd, nullptr, nullptr)};
    }
};

/// ===========================================================================
///  TCP Client
/// ===========================================================================
struct client : detail::tcp_base {
    client() = default;
    client(std::string_view host, u16 port) { connect(host, port); }
    ~client() { close(); }
    nocopy(client);
    client(client&& other) noexcept = default;
    client& operator=(client&& other) noexcept = default;

    /// Connect to a server.
    ///
    /// \param host Hostname or IP address.
    /// \param port Port number.
    /// \throw std::runtime_error if there is an error.
    void connect(std::string_view host, u16 port) {
        /// Create the socket.
        if (fd != -1) ::close(fd);
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) throw std::runtime_error("socket() failed");

        /// Resolve host.
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (auto code = ::getaddrinfo(host.data(), nullptr, &hints, &res); code != 0) {
            ::close(fd);
            fd = -1;
            throw std::runtime_error(fmt::format("getaddrinfo() failed: %s", gai_strerror(code)));
        }
        defer { ::freeaddrinfo(res); };

        /// Connect.
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = ::htons(port);
        addr.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            ::close(fd);
            fd = -1;
            throw std::runtime_error("connect() failed");
        }
    }
};

} // namespace net::tcp

#endif // NET_TCP_HH
