#ifndef NET_SSL_HH
#define NET_SSL_HH

#include "tcp.hh"

#include <functional>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#    error "OpenSSL version 1.1.0 or higher is required"
#endif

namespace net::ssl {
namespace detail {

} // namespace detail

/// SSL client.
///
/// Even though it has some builtin checks, this client is NOT thread-safe. Do
/// not use it across multiple threads.
class client {
    SSL_CTX* ctx = nullptr;
    BIO* bio = nullptr;
    SSL* ssl = nullptr;
    bool connected = false;
    bool stop_receiving = false;
    bool thread_running = false;
    std::thread recv_thread;
    std::mutex mtx;
    std::condition_variable cv;
    std::exception_ptr recv_exception = nullptr;
    std::vector<char> recv_buffer;
    std::string host_name;

    /// Get the current error message.
    [[nodiscard]] std::string geterr() {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof buf);
        return buf;
    }

    /// Raise an error.
    template <typename... arguments>
    [[noreturn]] void raise(fmt::format_string<arguments...> format, arguments&&... args) {
        std::string message = fmt::format(format, std::forward<arguments>(args)...);
        message += fmt::format(": {}", geterr());
        throw std::runtime_error(message);
    }

public:
    client() = default;
    client(std::string_view host, u16 port) { connect(host, port); }
    ~client() { close(); }
    nocopy(client);
    client(client&& other) noexcept : ctx(nullptr), bio(nullptr), ssl(nullptr) { *this = std::move(other); }
    client& operator=(client&& other) noexcept {
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
        ctx = other.ctx;
        bio = other.bio;
        ssl = other.ssl;
        connected = other.connected;
        stop_receiving = false;
        thread_running = false;
        recv_exception = std::move(other.recv_exception);
        recv_buffer = std::move(other.recv_buffer);
        other.ctx = nullptr;
        other.bio = nullptr;
        other.ssl = nullptr;
        other.connected = false;
        other.stop_receiving = false;
        other.recv_exception = nullptr;
        other.recv_buffer = {};

        /// Restart the thread if needed.
        if (restart) { recv_async(); }
        return *this;
    }

    /// Returns the current host name or the empty string if not connected.
    [[nodiscard]] std::string_view host() const { return host_name; }

    /// Get the data stored in the receive buffer.
    /// \throw std::runtime_error if the receive thread errored.
    std::vector<char> buffer() {
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

    /// Connect to a server.
    ///
    /// \param host The host to connect to.
    /// \param port The port to connect to.
    /// \throws std::runtime_error If the connection fails.
    void connect(std::string_view host, u16 port) {
        /// Make sure we don't connect twice.
        if (connected) raise("SSL client already connected");

        /// Wait for the receive thread to stop if we're reusing this client.
        while (stop_receiving and thread_running) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        std::unique_lock lock{mtx};

        /// Let openssl figure out the TLS version.
        const SSL_METHOD* method = TLS_client_method();
        if (not method) raise("OpenSSL: TLS_client_method() failed");

        /// Create the SSL context.
        ctx = SSL_CTX_new(method);
        if (not ctx) raise("OpenSSL: SSL_CTX_new() failed");
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_verify_depth(ctx, 4);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

        /// Load the trusted CA certificates.
        if (SSL_CTX_set_default_verify_file(ctx) != 1) raise("OpenSSL: SSL_CTX_set_default_verify_file() failed");
        if (SSL_CTX_set_default_verify_dir(ctx) != 1) raise("OpenSSL: SSL_CTX_set_default_verify_dir() failed");
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) raise("OpenSSL: SSL_CTX_set_default_verify_paths() failed");

        /// Connect to the server.
        bio = BIO_new_ssl_connect(ctx);
        if (not bio) raise("OpenSSL: BIO_new_ssl_connect() failed");

        /// Set the BIO to non-blocking mode.
        BIO_set_nbio(bio, 1);

        /// Set the hostname for the BIO.
        auto host_port = fmt::format("{}:{}", host, port);
        auto res = BIO_set_conn_hostname(bio, host_port.c_str());
        if (res != 1) raise("OpenSSL: BIO_set_conn_hostname() failed");

        /// Get the SSL object from the BIO.
        BIO_get_ssl(bio, &ssl);
        if (not ssl) raise("OpenSSL: BIO_get_ssl() failed");

        /// Retry the connection if it fails.
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        /// Set SSL cipher list.
        res = SSL_set_cipher_list(ssl, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
        if (res != 1) raise("OpenSSL: SSL_set_cipher_list() failed");

        /// Set the hostname for the SSL object.
        res = SSL_set_tlsext_host_name(ssl, host.data());
        if (res != 1) raise("OpenSSL: SSL_set_tlsext_host_name() failed");

        /// Connect to the server.
        for (;;) {
            res = BIO_do_connect(bio);
            if (res != 1) {
                if (not BIO_should_retry(bio)) raise("OpenSSL: BIO_do_connect() failed");
                continue;
            }
            break;
        }

        /// Perform the TLS handshake.
        for (;;) {
            res = BIO_do_handshake(bio);
            if (res != 1) {
                if (not BIO_should_retry(bio)) raise("OpenSSL: BIO_do_handshake() failed");
                continue;
            }
            break;
        }

        /// Verify the server certificate.
        X509* cert = SSL_get_peer_certificate(ssl);
        if (not cert) raise("OpenSSL: SSL_get_peer_certificate() failed");
        defer { free(cert); };

        /// Verify the chain.
        res = SSL_get_verify_result(ssl);
        if (res != X509_V_OK) raise("OpenSSL: Could not verify remote certificate");

        /// Verify the hostname.
        res = X509_check_host(cert, host.data(), host.size(), 0, nullptr);
        if (res != 1) raise("OpenSSL: Could not verify remote certificate hostname");

        /// We're connected!
        host_name = host;
        connected = true;
    }

    /// Close the connection.
    void close() {
        if (bio) {
            BIO_free_all(bio);
            bio = nullptr;
        }

        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }

        if (recv_thread.joinable()) {
            stop_receiving = true;
            recv_thread.join();
        }

        connected = false;
    }

    /// Send data to the server.
    ///
    /// \param data The data to send.
    /// \param size The size of the data to send (in bytes).
    /// \throws std::runtime_error If the send fails.
    void send(const char* data, size_t size) {
        if (not connected) raise("SSL client not connected");
        if (size > std::numeric_limits<int>::max()) raise("SSL client send size too large");

        /// Send the data.
        std::unique_lock lock{mtx};
        auto res = BIO_write(bio, data, int(size));
        if (res != int(size)) raise("OpenSSL: BIO_write() failed");
    }

    /// Send data to the server.
    ///
    /// \param data The data to send.
    /// \throws std::runtime_error If the send fails.
    template <typename data_t>
    void send(data_t&& data) { send(data.data(), data.size()); }

    /// Receive data from the server.
    ///
    /// \param data The buffer to receive the data into.
    /// \param size The size of the buffer (in bytes).
    /// \param us_timeout How long to wait between each attempted receive (in microseconds).
    /// \returns The number of bytes received.
    /// \throws std::runtime_error If the receive fails.
    template <bool lck = true>
    size_t recv(char* data, size_t size, size_t us_interval = 50) {
        if (not connected) raise("SSL client not connected");
        if (thread_running and std::this_thread::get_id() != recv_thread.get_id()) raise("Cannot recv() while receive thread is running");
        if (not size or size > std::numeric_limits<int>::max()) raise("SSL client recv must be between 1 and {}", std::numeric_limits<int>::max());

        /// Receive data.
        for (;;) {
            std::unique_lock lock{mtx, std::defer_lock};
            if constexpr (lck) lock.lock();
            auto n_read = BIO_read(bio, data, int(size));
            if (n_read < 0) {
                if (not BIO_should_retry(bio)) raise("OpenSSL: BIO_read() failed");
                if constexpr (lck) lock.unlock();
                std::this_thread::sleep_for(std::chrono::microseconds(us_interval));
                continue;
            }
            return n_read;
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
        if (not connected) raise("SSL client not connected");
        if (thread_running) raise("SSL client already receiving");
        if (stop_receiving) raise("SSL client shutting down");

        /// Create the receive thread.
        recv_thread = std::thread([this]() {
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
};

} // namespace net::ssl

#endif // NET_SSL_HH
