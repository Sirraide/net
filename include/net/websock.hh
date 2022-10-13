#ifndef NET_WEBSOCK_HH
#define NET_WEBSOCK_HH

#include "http.hh"
#include "tcp.hh"

#include <condition_variable>

namespace net::websock {
struct client {
    /// Connexion state.
    enum struct st {
        connecting
    } state = st::connecting;

    http::detail::curl curl;

    /// Connect to a websocket server.
    ///
    /// \param url The path to connect to.
    /// \throws std::runtime_error If the connection fails.
    explicit client(std::string_view url) {
        /// TODO: Parse and validate URL.
        bool secure = url.starts_with("wss://");

        /// Connect to the server.
        auto port = secure ? 443 : 80;

        /// Setup the TLS handshake if necessary.
        if (secure) {
            curl.setopt(CURLOPT_VERBOSE, 1L);
            curl.setopt(CURLOPT_SSL_VERIFYPEER, 1L);
            curl.setopt(CURLOPT_SSL_VERIFYHOST, 1L);
            curl.setopt(CURLOPT_TCP_KEEPALIVE, 1L);
            curl.setopt(CURLOPT_TCP_KEEPIDLE, 60L);
        }

        /// Connect to the server.
        curl.setopt(CURLOPT_URL, url.data());
        curl.setopt(CURLOPT_CONNECT_ONLY, 2L); /// WebSocket
        curl.setopt(CURLOPT_PORT, (long) port);
        curl();
    }

    ~client() = default;
    nocopy(client);
    nomove(client);

};
} // namespace net::websock

#endif // NET_WEBSOCK_HH
