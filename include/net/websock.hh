#ifndef NET_WEBSOCK_HH
#define NET_WEBSOCK_HH

#include "http.hh"
#include "tcp.hh"
#include "asm.hh"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <span>

namespace net::websock {
using namespace net::http;

/// Websocket frame header.
struct frame_header {
    u8 fin : 1;
    u8 rsv1 : 1;
    u8 rsv2 : 1;
    u8 rsv3 : 1;
    u8 opcode : 4;
    u8 mask : 1;
    u8 len : 7;
};

/// Websocket client as defined in RFC 6455.
template <typename backend_t = net::ssl::client>
class client : net::http::client<backend_t> {
    static_assert(std::is_same_v<backend_t, net::ssl::client> || std::is_same_v<backend_t, net::tcp::client>);

    /// HTTP client.
    using base = net::http::client<backend_t>;
    using base::conn;
    using base::perform;

    /// Send a websocket frame.
    void send_frame(u8 opcode, octets&& data) {
        /// Base header.
        frame_header hdr{};
        hdr.fin = 1;
        hdr.rsv1 = 0;
        hdr.rsv2 = 0;
        hdr.rsv3 = 0;
        hdr.opcode = opcode;
        hdr.mask = 1;
        hdr.len = data.size() < 126 ? data.size() : (data.size() < 65536 ? 126 : 127);
        conn.send(std::span(reinterpret_cast<const u8*>(&hdr), sizeof hdr));

        /// The payload length may be larger than 126 bytes.
        if (data.size() >= 126) {
            if (data.size() >= 65536) {
                u64 len = data.size();
                conn.send(std::span(reinterpret_cast<const u8*>(&len), sizeof len));
            } else {
                u16 len = data.size();
                conn.send(std::span(reinterpret_cast<const u8*>(&len), sizeof len));
            }
        }

        /// The mask is a 32-bit value.
        int mask = 0;
        RAND_bytes(reinterpret_cast<u8*>(&mask), sizeof mask);

        /// Send the mask.
        conn.send(std::span(reinterpret_cast<const u8*>(&mask), sizeof mask));

        /// Send the data.
        net::detail::memxor32(data.data(), data.size(), mask);
        conn.send(std::move(data));
    }

public:
    enum connection_state {
        connecting,
        open,
    } state = connecting;

    /// Connect to a websocket server.
    ///
    /// \param raw_url The websocket to connect to. The url must start with `ws://` or `wss://`.
    /// \throw std::runtime_error If the connection fails.
    explicit client(std::string_view raw_url) {
        /// Parse URL.
        const bool secure = raw_url.starts_with("wss://");
        if (not raw_url.starts_with("wss://") and not raw_url.starts_with("ws://")) {
            throw std::runtime_error("Not a websocket url");
        }
        raw_url.remove_prefix(secure ? 6 : 5);
        url url(raw_url);

        /// Make sure our backend is an SSL client if this is a wss:// url.
        if constexpr (is<backend_t, net::ssl::client>) {
            if (not secure) {
                throw std::runtime_error("Cannot connect to a ws:// url with an SSL backend");
            }
        } else {
            if (secure) {
                throw std::runtime_error("Cannot connect to a wss:// url with a non-SSL backend");
            }
        }

        /// Connect to the server.
        auto port = secure ? 443 : 80;
        conn.connect(url.host, port);

        /// Random key.
        octets unencoded_key;
        unencoded_key.resize(16);
        RAND_bytes(unencoded_key.data(), static_cast<i32>(unencoded_key.size()));

        /// Base64-encode the key.
        std::string encoded_key;
        encoded_key.resize(EVP_ENCODE_LENGTH(unencoded_key.size()));
        auto sz = EVP_EncodeBlock(
            reinterpret_cast<u8*>(encoded_key.data()),
            unencoded_key.data(),
            static_cast<i32>(unencoded_key.size())
        );
        encoded_key.resize(sz);

        /// Send the HTTP upgrade request.
        request req;
        req.meth = method::get;
        req.uri = url;
        req.hdrs["Upgrade"] = "websocket";
        req.hdrs["Connection"] = "Upgrade";
        req.hdrs["Sec-WebSocket-Key"] = encoded_key;
        req.hdrs["Sec-WebSocket-Version"] = "13";
        auto res = perform(req);

        /// Check the response.
        static const auto fail = [] { throw std::runtime_error("Websocket upgrade failed"); };
        if (res.status != 101) fail();
        if (auto up = res.hdrs["Upgrade"]; not up or *up != "websocket") fail();
        if (auto con = res.hdrs["Connection"]; not con or *con != "Upgrade") fail();

        /// For now, we don't allow extensions or subprotocols.
        if (res.hdrs["Sec-WebSocket-Extensions"]) throw std::runtime_error("Websocket extensions not supported");
        if (res.hdrs["Sec-WebSocket-Protocol"]) throw std::runtime_error("Websocket subprotocols not supported");

        /// The version must include 13.
        if (auto ver = res.hdrs["Sec-WebSocket-Version"]; not ver or ver->find("13") == std::string::npos) fail();

        /// Verify that we have a Sec-WebSocket-Accept header.
        auto accept = res.hdrs["Sec-WebSocket-Accept"];
        if (not accept) fail();

        /// The value of the header must be equal to the base64-encoded SHA-1 of the
        /// concatenation of the |Sec-WebSocket-Key| (as a string, not base64-decoded)
        /// with the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" but ignoring any leading
        /// and trailing whitespace.
        static constexpr const char magic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        static constexpr auto magic_len = sizeof(magic) - 1;
        octets expected_accept = unencoded_key;
        expected_accept.insert(expected_accept.end(), magic, magic + magic_len);

        /// Hash the expected accept header.
        octets expected_accept_hash;
        expected_accept_hash.resize(EVP_MAX_MD_SIZE);
        u32 expected_accept_hash_len;
        auto code = EVP_Digest(
            expected_accept.data(),
            static_cast<i32>(expected_accept.size()),
            expected_accept_hash.data(),
            &expected_accept_hash_len,
            EVP_sha1(),
            nullptr
        );
        if (code != 1) fail();
        expected_accept_hash.resize(expected_accept_hash_len);

        /// Base64 encode the hash.
        std::string expected_accept_encoded;
        expected_accept_encoded.resize(EVP_ENCODE_LENGTH(expected_accept_hash.size()));
        sz = EVP_EncodeBlock(
            reinterpret_cast<u8*>(expected_accept_encoded.data()),
            expected_accept_hash.data(),
            static_cast<i32>(expected_accept_hash.size())
        );
        expected_accept_encoded.resize(sz);

        /// Make sure the accept header matches.
        if (expected_accept_encoded != *accept) fail();

        /// We're connected!
        state = open;
    }
};
} // namespace net::websock

#endif // NET_WEBSOCK_HH
