#ifndef NET_WEBSOCK_HH
#define NET_WEBSOCK_HH

#include "asm.hh"
#include "http.hh"
#include "tcp.hh"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <span>

namespace net::websock {
using namespace net::http;

/// Websocket frame header.
struct frame_header {
    u8 fin : 1;
    u8 rsv1 : 1 = 0;
    u8 rsv2 : 1 = 0;
    u8 rsv3 : 1 = 0;
    u8 opcode : 4;
    u8 mask : 1;
    u8 len : 7;
};

enum struct opcode : u8 {
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
};

struct message {
    recvbuffer buffer;
    opcode type;

    /// Returns the message data.
    [[nodiscard]] std::span<u8> data() { return buffer.span(); }
    [[nodiscard]] std::span<const u8> data() const { return buffer.span(); }
};

/// Websocket client as defined in RFC 6455.
template <typename backend_t = net::ssl::client>
class client : net::http::client<backend_t> {
    static_assert(std::is_same_v<backend_t, net::ssl::client> || std::is_same_v<backend_t, net::tcp::client>);

    /// HTTP client.
    using base = net::http::client<backend_t>;
    using base::conn;
    using base::perform;

public:
    enum struct connection_state {
        connecting,
        open,
    } state = connection_state::connecting;

    /// Called whenever a `text` message is received.
    std::function<void(message&&)> on_text;

    /// Called whenever a `binary` message is received.
    std::function<void(message&&)> on_binary;

    /// Called whenever a `close` message is received. The implementation will
    /// always close the connexion after the callback returns.
    std::function<void(message&&)> on_close;

    /// Called whenever a `ping` message is received.
    std::function<void(message&&)> on_ping;

    /// Called whenever a `pong` message is received.
    std::function<void(message&&)> on_pong;

    /// Called whenever an unknown message is received.
    std::function<void(message&&)> on_unknown;

    /// Client constructor. This installs default callbacks.
    client() {
        on_ping = [this](message&& msg) { send_frame(opcode::pong, msg.data()); };
        on_unknown = [this](message&& msg) {
            u16 code = htons(1002);
            send_frame(opcode::close, {reinterpret_cast<u8*>(code), sizeof code});
        };
    }

    /// Close the connexion when this is destroyed.
    ~client() { close(); }

    /// Close the connexion forcefully.
    void close() {
        if (state == connection_state::open) {
            send_frame(opcode::close, {});
            state = connection_state::connecting;
        }
    }

    /// Connect to a websocket server.
    ///
    /// This will block until the connexion is terminated by the server, so make
    /// sure to start this in a separate thread if you want to continue doing other
    /// things.
    ///
    /// \param raw_url The websocket to connect to. The url must start with `ws://` or `wss://`.
    /// \throw std::runtime_error If the connection fails.
    void connect(std::string_view raw_url) {
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
        state = connection_state::open;

        /// Run the read loop.
        while (state == connection_state::open) {
            /// Read a message.
            auto m = recvmsg();

            /// Dispatch the message.
            switch (m.type) {
                case opcode::text:
                    /// Text message.
                    if (on_text) on_text(std::move(m));
                    break;
                case opcode::binary:
                    /// Binary message.
                    if (on_binary) on_binary(std::move(m));
                    break;
                case opcode::close:
                    /// Close message.
                    if (on_close) on_close(std::move(m));
                    close();
                    break;
                case opcode::ping:
                    /// Ping message.
                    if (on_ping) on_ping(std::move(m));
                    break;
                case opcode::pong:
                    /// Pong message.
                    if (on_pong) on_pong(std::move(m));
                    break;
                default:
                    /// Unknown opcode.
                    if (on_unknown) on_unknown(std::move(m));
                    break;
            }
        }
    }

    /// Shut the connection down gracefully.
    void shutdown() {
        if (state == connection_state::open) send_frame(opcode::close, {});
    }

private:
    /// Send a websocket frame.
    void send_frame(opcode op, std::span<u8> data = {}) {
        /// We can't send frames if we're not connected.
        if (state != connection_state::open) {
            /// Allow duplicate close frames.
            if (op != opcode::close) throw std::runtime_error("Not connected");
            return;
        }

        /// Base header.
        frame_header hdr{};
        hdr.fin = 1;
        hdr.opcode = static_cast<u8>(op);
        hdr.mask = 1;

        /// Send the data if there is any.
        if (not data.empty()) {
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
            auto res = RAND_bytes(reinterpret_cast<u8*>(&mask), sizeof mask);
            if (res != 1) throw std::runtime_error("Could not generate masking key");

            /// Send the mask.
            conn.send(std::span(reinterpret_cast<const u8*>(&mask), sizeof mask));

            /// Send the data.
            net::detail::memxor32(data.data(), data.size(), mask);
            conn.send(data);
            return;
        }

        /// Just send the header and a dummy masking key if there is no data.
        conn.send(std::span(reinterpret_cast<const u8*>(&hdr), sizeof hdr));
        int mask = 0;
        conn.send(std::span(reinterpret_cast<const u8*>(&mask), sizeof mask));
    }

    /// Receive a websocket message.
    [[nodiscard]] message recvmsg() {
        if (state != connection_state::open) throw std::runtime_error("Not connected");

        /// Buffer to hold the received data.
        message mess;
        auto& [buffer, type] = mess;

        /// The data may be split into multiple frames. Keep reading until we get a
        /// frame with the FIN bit set.
        for (;;) {
            /// Make sure we have enough space to read the header.
            auto start = buffer.offs();
            buffer.allocate(1024);

            /// Receive the header.
            conn.recv(buffer, sizeof(frame_header));

            /// Parse the header.
            auto& hdr = buffer.extract<frame_header>();
            if (not std::underlying_type_t<opcode>(type)) type = static_cast<opcode>(hdr.opcode);

            /// The payload length may be larger than 126 bytes.
            u64 len = hdr.len;
            if (len == 126) {
                conn.recv(buffer, sizeof(u16));
                len = buffer.extract<u16>();
            } else if (len == 127) {
                conn.recv(buffer, sizeof(u64));
                len = buffer.extract<u64>();
            }

            /// Make sure we have enough space to read the rest of the frame. We always
            /// include 8 bytes for the length and 4 for the mask, even if they are not
            /// used.
            buffer.allocate(len + sizeof(u64) + sizeof(u32));

            /// The mask is a 32-bit value.
            if (hdr.mask) {
                i32 mask;
                conn.recv(buffer, len + sizeof mask);
                mask = buffer.extract<i32>();
                net::detail::memxor32(buffer.data(), len, mask);
            } else {
                conn.recv(buffer, len);
            }

            /// Check if this is the last frame. We need to save this value because
            /// deleting the metadata below will invalidate the reference to the header.
            const bool fin = hdr.fin;

            /// Erase the metadata.
            buffer.erase_to_offset(start);

            /// Return the data if this is the last frame.
            if (fin) {
                buffer.reset();
                return mess;
            }
        }
    }
};
} // namespace net::websock

#endif // NET_WEBSOCK_HH
