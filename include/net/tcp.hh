#ifndef NET_TCP_HH
#define NET_TCP_HH

#include "common.hh"
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
protected:
    using error = std::runtime_error;

    int fd = -1;
    bool connected = false;
    std::string host_name;

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
    nomove(tcp_base);

    /// Close the socket.
    void close() {
        if (fd != -1) {
            ::close(fd);
            fd = -1;
        }

        connected = false;
    }

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

    /// Send a message.
    ///
    /// \param msg The message to send.
    /// \throw std::runtime_error if the call to ::send() fails.
    template <typename message>
    void send(message&& msg) {
        if (not connected) throw error("Cannot send data on a disconnected socket");
        auto n = ::send(fd, msg.data(), msg.size(), 0);
        if (n == -1) raise("send() failed");
    }

    /// Receive more data.
    ///
    /// \param buffer The buffer to receive into
    /// \param bytes The number of bytes to receive.
    void recv(recvbuffer& v, size_t bytes = 0) {
        v.allocate(bytes);
        v.grow(recv(v.data(), v.capacity(), bytes));
    }

    /// Receive data from the server.
    ///
    /// \param data The buffer to receive the data into.
    /// \param size The size of the buffer (in bytes).
    /// \param at_least The number of bytes to receive. This function will loop
    ///      until at least this many bytes have been received.
    /// \returns The number of bytes received.
    /// \throws std::runtime_error If the receive fails.
    u64 recv(u8* data, u64 size, u64 at_least = 1) {
        if (not connected) throw error("Cannot receive data on a disconnected socket");
        if (at_least > size) throw error("Cannot receive more data than the buffer can hold");

        /// Receive data.
        u64 n_read{};
        for (;;) {
            auto ret = ::recv(fd, data, size, 0);
            if (ret < 0 and errno != EINTR and errno != EAGAIN) raise("recv() failed");
            n_read += ret;
            if (n_read >= at_least) return n_read;
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

    /// A server can't connect to anything.
    void connect(std::string_view host, u16 port) = delete;

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

    /// Returns the current host name or the empty string if not connected.
    [[nodiscard]] std::string_view host() const { return host_name; }
};

} // namespace net::tcp

#endif // NET_TCP_HH
