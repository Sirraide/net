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
    nomove(client);

    /// Returns the current host name or the empty string if not connected.
    [[nodiscard]] std::string_view host() const { return host_name; }

    /// Connect to a server.
    ///
    /// \param host The host to connect to.
    /// \param port The port to connect to.
    /// \throws std::runtime_error If the connection fails.
    void connect(std::string_view host, u16 port) {
        /// Make sure we don't connect twice.
        if (connected) raise("SSL client already connected");

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

        connected = false;
    }

    /// Send data to the server.
    ///
    /// \param data The data to send.
    /// \param size The size of the data to send (in bytes).
    /// \throws std::runtime_error If the send fails.
    void send(const void* data, size_t size) {
        if (not connected) raise("SSL client not connected");
        if (size > std::numeric_limits<int>::max()) raise("SSL client send size too large");

        /// Send the data.
        auto res = BIO_write(bio, data, int(size));
        if (res != int(size)) raise("OpenSSL: BIO_write() failed");
    }

    /// Send data to the server.
    ///
    /// \param data The data to send.
    /// \throws std::runtime_error If the send fails.
    template <typename data_t>
    void send(data_t&& data) { send(data.data(), data.size()); }

    /// Receive more data.
    ///
    /// If the buffer already contains `bytes` bytes, this function will return immediately.
    ///
    /// \param buffer The buffer to receive into
    /// \param bytes The number of bytes to receive. A value of `0` means that
    ///     the implementation will always perform a call to recv() and that
    ///     it will only call recv() once.
    void recv(recvbuffer& v, size_t bytes = 0) {
        if (bytes and v.size() >= bytes) return;
        v.allocate(bytes ?: 4096);
        v.grow(recv(v.data(), std::min<u64>(v.capacity(), std::numeric_limits<int>::max()), bytes));
    }

    /// Receive data from the server.
    ///
    /// \param data The buffer to receive the data into.
    /// \param size The size of the buffer (in bytes).
    /// \param at_least The number of bytes to receive. This function will loop
    ///      until at least this many bytes have been received.
    /// \returns The number of bytes received.
    /// \throws std::runtime_error If the receive fails.
    u64 recv(void* data, u64 size, u64 at_least = 1) {
        if (not connected) raise("SSL client not connected");
        if (not size or size > std::numeric_limits<int>::max()) raise("SSL client recv() size must be between 1 and {}, but was {}", std::numeric_limits<int>::max(), size);

        /// Receive data.
        u64 n_read{};
        for (;;) {
            auto ret = BIO_read(bio, data, int(size));
            if (ret < 0) {
                if (not BIO_should_retry(bio)) raise("OpenSSL: BIO_read() failed");
                continue;
            }
            n_read += ret;
            if (n_read >= at_least) return n_read;
        }
    }
};

} // namespace net::ssl

#endif // NET_SSL_HH
