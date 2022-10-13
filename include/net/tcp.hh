#ifndef NET_TCP_HH
#define NET_TCP_HH

#include "utils.hh"

#include <arpa/inet.h>
#include <condition_variable>
#include <mutex>
#include <netdb.h>
#include <thread>

namespace net::tcp {
namespace detail {
/// Data and functions that are common to both client and server.
struct tcp_base {
    int fd = -1;

private:
    std::string buffer;
    std::mutex mtx;
    std::condition_variable cv;
    std::atomic_flag receiving = ATOMIC_FLAG_INIT;
    bool stop_receiving = false;

public:
    /// Make sure we don't forget to close the socket.
    tcp_base() = default;
    tcp_base(int fd, bool start = false) : fd(fd) {
        if (start) start_receiving();
    }
    ~tcp_base() { close(); }
    nocopy(tcp_base);
    nomove(tcp_base);

    /// Close the socket.
    void close() {
        if (fd != -1) {
            stop_receiving = true;
            cv.notify_all();
            ::close(fd);
            fd = -1;
        }
    }

    /// Start receiving data.
    void start_receiving(u64 at_most = std::numeric_limits<u64>::max()) {
        /// Make sure we don't start receiving twice.
        if (receiving.test_and_set()) return;

        /// Set a receive timeout.
        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;
        auto res = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
        if (res == -1) throw std::runtime_error("setsockopt() failed");

        /// Start receiving asynchronously.
        std::thread([this, at_most] {
            char buf[1024];
            while (not stop_receiving) {
                /// Read data from the socket.
                auto n = ::recv(fd, buf, sizeof(buf), 0);
                if (n == -1) {
                    if (errno == EINTR or errno == EAGAIN or errno == EWOULDBLOCK) continue;
                    if (errno == ECONNABORTED or errno == ECONNRESET or errno == ECONNREFUSED) return;
                    throw std::runtime_error("recv() failed");
                }
                if (n == 0) continue;

                /// Append the data to the buffer.
                std::unique_lock lock{mtx};
                buffer.append(buf, n);
                cv.notify_all();

                /// Defer receiving more data if we have enough.
                if (buffer.size() >= at_most) cv.wait(lock, [this, at_most] { return buffer.size() < at_most or stop_receiving; });
            }
        }).detach();
    }

    /// Send a message.
    ///
    /// \param msg The message to send.
    /// \throw std::runtime_error if the call to ::send() fails.
    void send(std::string_view msg) const {
        auto n = ::send(fd, msg.data(), msg.size(), 0);
        if (n == -1) throw std::runtime_error("send() failed");
    }

    /// Read data from the socket.
    ///
    /// \param at_most The maximum number of bytes to read.
    /// \return The data read from the socket.
    std::string recv(u64 at_most = std::numeric_limits<u64>::max()) {
        if (not receiving.test()) throw std::runtime_error("start_receiving() must be called before recv()");
        std::unique_lock lock{mtx};
        cv.wait(lock, [this] { return not buffer.empty() or stop_receiving; });
        auto res = buffer.substr(0, at_most);
        buffer.erase(0, at_most);
        return res;
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
    nomove(server);

    /// Listen on a port.
    ///
    /// \param port Port number.
    /// \throw std::runtime_error if there is an error.
    void listen(u16 port, int max_connexions = 128) {
        /// A negative number of connexions is nonsense.
        if (max_connexions < 1) throw std::runtime_error("max_connexions must be >= 1");

        /// Create the socket.
        if (fd != -1) ::close(fd);
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) throw std::runtime_error("socket() failed");

        /// Bind to port.
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = ::htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            ::close(fd);
            fd = -1;
            throw std::runtime_error("bind() failed");
        }

        /// Listen.
        if (::listen(fd, max_connexions) == -1) {
            ::close(fd);
            fd = -1;
            throw std::runtime_error("listen() failed");
        }
    }

    /// Accept a connexion.
    /// \throw std::runtime_error if there is an error.
    [[nodiscard]] connexion accept() const {
        return connexion{::accept(fd, nullptr, nullptr), true};
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
    nomove(client);

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

        start_receiving();
    }
};

} // namespace net::tcp

#endif // NET_TCP_HH
