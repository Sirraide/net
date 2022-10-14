#ifndef NET_WEBSOCK_HH
#define NET_WEBSOCK_HH

#include "http.hh"
#include "tcp.hh"

#include <openssl/ssl.h>

namespace net::websock {
struct client {
    /// Connexion state.
    enum struct st {
        connecting
    } state = st::connecting;

    tcp::client tcp;
    SSL_CTX *ctx = nullptr;

    /// Connect to a websocket server.
    ///
    /// \param url The path to connect to.
    /// \throws std::runtime_error If the connection fails.
    explicit client(std::string_view url) {
        /// TODO: Parse and validate URL.
        const bool secure = url.starts_with("wss://");

        /// TODO: There MUST be no more than one connection in a CONNECTING state.

        /// Connect to the server.
        const auto port = secure ? 443 : 80;
        tcp.connect(url.substr(secure ? 6 : 5), port);

        /// Perform a TLS handshake using openssl if needed.
        if (secure) {
            /// Perform a TLS handshake using openssl


        }


    }

    ~client() = default;
    nocopy(client);
    nomove(client);

};
} // namespace net::websock

#endif // NET_WEBSOCK_HH
