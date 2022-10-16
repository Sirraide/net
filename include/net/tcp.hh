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
    std::thread recv_thread;
    std::exception_ptr recv_exception = nullptr;
    std::vector<char> recv_buffer;
    std::mutex mtx;
    std::condition_variable cv;

protected:
    using error = std::runtime_error;

    int fd = -1;
    bool connected = false;

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
    tcp_base(tcp_base&& other) : fd(-1) { *this = std::move(other); }
    tcp_base& operator=(tcp_base&& other) {
        if (this == std::addressof(other)) { return *this; }

        /// Shut us down.
        std::unique_lock lock{mtx};
        if (thread_running) {
            stop_receiving = true;
            cv.wait(lock, [this] { return not thread_running; });
            recv_thread.join();
        }
        close();

        /// Take over the other connexion.
        std::unique_lock other_lock{other.mtx};

        /// We need to stop and restart the other thread if it's running.
        bool restart = other.thread_running;
        if (restart) {
            other.stop_receiving = true;
            other.cv.wait(other_lock, [&other] { return not other.thread_running; });
            other.recv_thread.join();
        }

        /// Move the connexion state.
        fd = other.fd;
        connected = other.connected;
        thread_running = false;
        stop_receiving = false;
        recv_exception = std::move(other.recv_exception);
        recv_buffer = std::move(other.recv_buffer);
        other.fd = -1;
        other.connected = false;
        other.stop_receiving = false;
        other.recv_exception = nullptr;
        other.recv_buffer = {};

        /// Restart the thread if needed.
        if (restart) { recv_async(); }
        return *this;
    }

    /// Get the data stored in the receive buffer.
    /// \throw std::runtime_error if the receive thread errored.
    [[nodiscard]] std::vector<char> buffer() {
        std::unique_lock lock{mtx};
        if (recv_exception) {
            auto except = std::move(recv_exception);
            recv_exception = nullptr;
            std::rethrow_exception(except);
        }
        auto ret = std::move(recv_buffer);
        recv_buffer = {};
        return ret;
    }

    /// Close the socket.
    void close() {
        if (fd != -1) {
            stop_receiving = true;
            ::close(fd);
            fd = -1;
        }

        if (recv_thread.joinable()) {
            recv_thread.join();
        }
    }

    /// Receive data in a separate thread.
    ///
    /// This creates a dedicated thread which repeatedly calls recv(), storing the received
    /// data in a buffer. The thread is joined when it errors, the client is destroyed, or close()
    /// or stop_receiving() is called.
    ///
    /// \throws std::runtime_error If the thread cannot be created.
    void recv_async() {
        if (not connected) throw error("Cannot receive data on a disconnected socket");
        if (thread_running) throw error("Client already receiving");
        if (stop_receiving) throw error("Client shutting down");

        /// Set a receive timeout.
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        auto res = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        if (res == -1) raise("setsockopt() failed");

        /// Start receiving asynchronously.
        recv_thread = std::thread([this] {
            /// Signal that the thread has exited.
            defer {
                thread_running = false;
                stop_receiving = false;
                cv.notify_all();
            };

            try {
                /// Grow the receive buffer as needed.
                static constexpr size_t grow_by = 1024;

                /// Clear the buffer.
                {
                    std::unique_lock lock{mtx};
                    thread_running = true;
                    recv_buffer.clear();
                }

                /// Receive data.
                while (not stop_receiving) {
                    /// Make sure we don't try to move this while we're receiving.
                    std::unique_lock lock{mtx};
                    if (stop_receiving) break;

                    /// Reserve more space in the buffer.
                    auto sz = recv_buffer.size();
                    if (recv_buffer.capacity() < sz + grow_by) recv_buffer.resize(sz + grow_by);

                    /// Receive data.
                    auto n_read = recv<false>(recv_buffer.data() + sz, recv_buffer.size() - sz, 100'000);
                    recv_buffer.resize(sz + n_read);
                }
            } catch (const std::exception& e) {
                std::unique_lock lock{mtx};
                recv_exception = std::make_exception_ptr(e);
            }
        });
    }

    /// Send a message.
    ///
    /// \param msg The message to send.
    /// \throw std::runtime_error if the call to ::send() fails.
    template <typename message>
    void send(message&& msg) {
        if (not connected) throw error("Cannot send data on a disconnected socket");
        std::unique_lock lock{mtx};
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
    template <bool lck = true>
    size_t recv(char* data, size_t size, size_t us_interval = 50) {
        if (thread_running and std::this_thread::get_id() != recv_thread.get_id()) throw error("Cannot recv() while receive thread is running");
        if (not size) return 0;

        /// Receive data.
        for (;;) {
            ssize_t n_read;
            if constexpr (lck) {
                std::unique_lock lock{mtx};
                n_read = ::recv(fd, data, size, 0);
                lock.unlock();
            } else {
                n_read = ::recv(fd, data, size, 0);
            }
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
class client : public detail::tcp_base {
    std::string host_name;

public:
    client() = default;
    client(std::string_view host, u16 port) { connect(host, port); }
    ~client() { close(); }
    nocopy(client);
    client(client&& other) noexcept = default;
    client& operator=(client&& other) noexcept = default;

    /// Returns the current host name or the empty string if not connected.
    [[nodiscard]] std::string_view host() const { return host_name; }

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

        /// We're connected!
        host_name = host;
        connected = true;
    }
};

} // namespace net::tcp

#endif // NET_TCP_HH
