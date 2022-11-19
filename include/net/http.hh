#ifndef NET_HTTP_HH
#define NET_HTTP_HH

#include "ssl.hh"
#include "utils.hh"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <variant>
#include <zlib.h>

namespace net::http {

namespace chrono = std::chrono;
using namespace std::chrono_literals;
using namespace std::string_literals;

/// HTTP Verbs.
enum struct method {
    get,
    head,
    post,
};

constexpr inline std::string_view method_to_str(method meth) {
    switch (meth) {
        case method::get: return "GET";
        case method::head: return "HEAD";
        case method::post: return "POST";
    }
    throw std::runtime_error("Invalid method");
}

/// HTTP headers.
template <bool case_insensitive = false>
struct smap_impl {
    std::unordered_map<std::string, std::string> values;

    smap_impl() = default;
    smap_impl(std::initializer_list<std::pair<const std::string, std::string>>&& init) {
        if constexpr (case_insensitive) {
            for (const auto& [k, v] : init) values[tolower(k)] = v;
        } else {
            values = init;
        }
    }

    /// Reference to a header value.
    struct smap_ref {
        smap_impl& parent;
        std::string key;

    private:
        friend struct smap_impl;

        /// Create a reference to a header value.
        smap_ref(smap_impl& parent, std::string&& key) : parent(parent), key(std::move(key)) {}

    public:
        /// Set the header value. This will append the value to the existing value,
        /// separated by a comma if the header already exists.
        smap_ref& operator=(std::string_view value) {
            if (parent.values.contains(key)) parent.values[key] += fmt::format(", {}", value);
            else parent.values[key] = value;
            return *this;
        }

        /// Check if the header exists.
        operator bool() { return parent.values.contains(key); }

        /// Get the header value.
        std::string& operator*() { return parent.values.at(key); }

        /// Get the header value.
        std::string* operator->() { return std::addressof(parent.values.at(key)); }
    };

    /// Get a reference to a header value.
    smap_ref operator[](std::string_view key) {
        if constexpr (case_insensitive) return {*this, tolower(key)};
        else return {*this, std::string{key}};
    }

    /// Check if there are elements in the map.
    bool empty() const { return values.empty(); }

    /// Check if a certain header exists.
    bool has(const std::string& key) {
        if constexpr (case_insensitive) return values.contains(tolower(key));
        else return values.contains(key);
    }
};

/// `smap` isn't very expressive.
using headers = smap_impl<true>;

/// The body of a request/response may contain 0 bytes, for which reason we
/// can't store it in a std::string.
using octets = std::vector<char>;

struct url {
    std::string scheme;
    std::string userinfo;
    std::string host;
    std::string path;
    std::string fragment;
    smap_impl<false> params;
    u16 port{};

    url() {}
    url(std::string_view);
};

/// HTTP Message.
struct http_message {
    headers hdrs;
    octets body;
    u32 proto;
};

/// HTTP response.
struct response : http_message {
    u32 status{};

    response& expect(u32 code) {
        if (status != code) throw std::runtime_error(fmt::format("Expected status {}, but was {}", code, status));
        return *this;
    }
};

/// HTTP request.
struct request : http_message {
    url uri;
    method meth = method::get;

    /// Create a request.
    explicit request() {}
    explicit request(url _uri, method _meth, headers _hdrs = {})
        : uri(std::move(_uri)), meth(_meth) {
        hdrs = std::move(_hdrs);
    }

    /// Send the request over a connexion.
    template <typename conn_t>
    void send(conn_t& conn) {
        std::string buf = fmt::format("{} {} HTTP/1.1\r\n", method_to_str(meth), uri.path);
        if (not uri.params.empty()) {
            buf += '?';
            bool first = true;
            for (const auto& [k, v] : uri.params.values) {
                if (not first) buf += '&';
                else first = false;
                buf += fmt::format("{}={}", k, v);
            }
        }

        for (const auto& [key, value] : hdrs.values) buf += fmt::format("{}: {}\r\n", key, value);
        buf += "\r\n";
        conn.send(buf);
    }
};

namespace detail {
/// States common to all parsers.
///
/// The states of different parsers are marked by a mask bit. This allows us to
/// nest parsers without having to worry about state collisions.
enum : u32 {
    request_parser_state = 0,
    response_parser_state = 0,

    st_done_state = 1,

    /// States for the uri parser.
    uri_parser_state = 1 << 20,

    /// States for the headers parser.
    headers_parser_state = 1 << 21,

    /// States for the body parser.
    body_parser_state = 1 << 22,

    /// States for the chunked encoding parser.
    chunked_parser_state = body_parser_state | (1 << 23),

    /// This flag indicates a state that the parser would like to process more input
    /// in, but if there isn't any, then that's fine too.
    accepts_more_flag = 1u << 31u,
};

/// State required for parsing an entity.
template <typename result>
struct parser_state;

/// Parsing context.
///
/// This is used by the URI, request, and response parsers.
template <typename result, auto parser_impl, u32 start_state>
requires std::is_same_v<std::remove_cvref_t<result>, result>
struct parser {
    /// The output of the parser.
    result& output;

    /// The parser’s current state.
    u32 state = start_state;

    /// Further state required by the parser.
    parser_state<result> data;

    /// Construct a parser.
    explicit parser(result& output) : output(output) {}

    /// Step the parser.
    ///
    /// \param input The input to parse.
    /// \return How much of the input was consumed.
    [[nodiscard]] u64 operator()(std::span<const char> input) {
        /// The parser is already done. No more input will be consumed.
        if (state == st_done_state) [[unlikely]]
            return 0;

        /// The parser would accept more input, but we don't have any to provide, so we're done.
        if (input.empty()) {
            if (state & accepts_more_flag) state = st_done_state;
            return 0;
        }

        /// Advance the parser.
        const char* const start = input.data();
        state = parser_impl(input, data, output, state);
        return input.data() - start;
    }

    /// How many characters the parser wants to consume.
    [[nodiscard]] u64 want() const {
        if constexpr (is<result, octets>) return data.len;
        else if constexpr (is<result, response> or is<result, request>) return data.body_parser.len;
        else return 0;
    }

    /// Check if the parser is done.
    [[nodiscard]] bool done() const { return state == st_done_state or state & accepts_more_flag; }
};

/// URI parser state.
template <>
struct parser_state<url> {
    std::string parse_buffer1;
    std::string parse_buffer2;
    u8 fst{};
};

/// Headers parser state.
template <>
struct parser_state<headers> {
    std::string name;
    std::string value;
};

/// Body parser state.
template <>
struct parser_state<octets> {
    u64 len{};
    parser_state<headers> hdrs_parser;
    bool is_response = false;
};

/// Request parser state.
template <>
struct parser_state<request> {
    parser_state<url> url_parser;
    parser_state<headers> hdrs_parser;
    parser_state<octets> body_parser;
};

/// Request parser state.
template <>
struct parser_state<response> {
    parser_state<headers> hdrs_parser;
    parser_state<octets> body_parser;
};

/// URI parser.
///
/// Currently, this cannot parse IPv6 addresses.
u32 parse_uri(std::span<const char>& input, parser_state<url>& parser, url& uri, u32 state);

/// HTTP headers parser.
///
/// This parses HTTP headers and the final CRLF that terminates them.
u32 parse_headers(std::span<const char>& input, parser_state<headers>& parser, headers& hdrs, u32 state);

/// HTTP request/response body parser.
///
/// \param input The input buffer.
/// \param message The message whose body we're parsing.
/// \param state The current state.
u32 parse_body(std::span<const char>& input, parser_state<octets>& parser, http_message& msg, u32 state);

/// HTTP request parser.
///
/// \param input The input buffer.
/// \param req The output request.
/// \param state The current state of the parser.
u32 parse_request(std::span<const char>& input, parser_state<request>& parser, request& req, u32 state);

/// HTTP response parser.
///
/// \param input The input buffer.
/// \param consumed How many characters have been consumed from the input buffer.
/// \param res The output response.
u32 parse_response(std::span<const char>& input, parser_state<response>& parser, response& res, u32 state);

using body_parser = parser<response, parse_body, body_parser_state>;
using uri_parser = parser<url, parse_uri, uri_parser_state>;
using headers_parser = parser<headers, parse_headers, headers_parser_state>;
using request_parser = parser<request, parse_request, request_parser_state>;
using response_parser = parser<response, parse_response, response_parser_state>;
} // namespace detail

template <typename backend_t = tcp::client, u16 default_port = std::is_same_v<backend_t, net::ssl::client> ? 443 : 80>
struct client {
protected:
    using backend_type = backend_t;
    recvbuffer buffer;
    backend_type conn;

public:
    explicit client() : conn() {}
    explicit client(std::string_view host_name, u16 port = default_port) : conn(host_name, port ?: default_port) {}

    /// Perform a request.
    ///
    /// \param req The request to perform.
    /// \param us_timeout How long to wait for a response (in microseconds).
    ///     A value of 0 means no timeout.
    /// \throw std::runtime_error If the request fails or if the response is invalid.
    /// \return The response.
    response perform(request&& req, chrono::microseconds us_timeout = 1s) {
        if (us_timeout < 0us) throw std::runtime_error("Timeout must be positive");

        /// Make sure the path isn’t empty.
        if (req.uri.path.empty()) req.uri.path = "/";

        /// Overwrite the host header with the host of the uri.
        if (not req.uri.host.empty()) req.hdrs["Host"] = req.uri.host;

        /// Send the request.
        if (not req.hdrs.has("Host")) req.hdrs["Host"] = conn.host();
        if (not req.hdrs.has("Connection")) req.hdrs["Connection"] = "keep-alive";
        if (not req.hdrs.has("Accept-Encoding")) req.hdrs["Accept-Encoding"] = "deflate, gzip";
        req.send(conn);

        /// Read the response.
        response res;
        [[maybe_unused]] auto now = chrono::high_resolution_clock::now();

        /// Create a parser.
        detail::response_parser parser{res};
        try {
            for (;;) {
                /// Allocate enough memory to read the entire body if we can.
                if (parser.state & detail::body_parser_state) buffer.allocate(parser.data.body_parser.len);

                /// Receive data.
                auto sz = buffer.size();
                conn.recv(buffer, parser.state & detail::body_parser_state ? parser.data.body_parser.len : 0);
                if (sz == buffer.size()) break;

                /// Advance the parser.
                auto consumed = parser(buffer);
                buffer.skip(consumed);

                /// Stop if we're done.
                if (parser.done()) break;

                /// Check if the timeout has been reached.
                if (us_timeout > 0us and chrono::high_resolution_clock::now() - now > us_timeout)
                    throw std::runtime_error("Timeout reached");
            }
        } catch (const timed_out&) {
            if (not parser.done()) throw std::runtime_error("Timeout reached");
        }

        /// Handle gzip, compress, and deflate using zlib’s C API.
        if (res.hdrs.has("Content-Encoding")) {
            enum {
                compress,
                deflate,
                gzip,
            } encoding;

            if (auto& enc = *res.hdrs["Content-Encoding"]; enc == "gzip" or enc == "x-gzip") encoding = gzip;
            else if (enc == "compress" or enc == "x-compress") encoding = compress;
            else if (enc == "deflate") encoding = deflate;
            else throw std::runtime_error(fmt::format("Unknown Content-Encoding: {}", enc));

            /// Create a stream.
            z_stream stream;
            stream.zalloc = Z_NULL;
            stream.zfree = Z_NULL;
            stream.opaque = Z_NULL;
            stream.avail_in = 0;
            stream.next_in = Z_NULL;

            /// Initialize the stream.
            if (encoding == gzip) {
                if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) throw std::runtime_error("inflateInit2 failed");
            } else if (encoding == compress) {
                if (inflateInit(&stream) != Z_OK) throw std::runtime_error("inflateInit failed");
            } else if (encoding == deflate) {
                if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) throw std::runtime_error("inflateInit2 failed");
            }

            /// Decompress the body.
            stream.avail_in = res.body.size();
            stream.next_in = reinterpret_cast<Bytef*>(res.body.data());
            octets decompressed;
            do {
                decompressed.resize(decompressed.size() + 1024);
                stream.avail_out = 1024;
                stream.next_out = reinterpret_cast<Bytef*>(decompressed.data() + decompressed.size() - 1024);
                auto ret = inflate(&stream, Z_NO_FLUSH);
                switch (ret) {
                    case Z_NEED_DICT:
                    case Z_DATA_ERROR:
                    case Z_MEM_ERROR:
                        inflateEnd(&stream);
                        throw std::runtime_error("inflate failed");
                    default: break;
                }
                decompressed.resize(decompressed.size() - stream.avail_out);
            } while (stream.avail_out == 0);
            inflateEnd(&stream);
            res.body = std::move(decompressed);
        }

        /// Done!
        buffer.erase_to_offset();
        return res;
    }

    /// Perform a GET request.
    ///
    /// \param uri The URI to GET.
    /// \param hdrs The headers to send.
    /// \return The response.
    response get(url url, headers hdrs = {}) {
        return perform(request{std::move(url), method::get, std::move(hdrs)});
    }

    /// Perform a GET request.
    ///
    /// \param path The path to GET.
    /// \param hdrs The headers to send.
    /// \return The response.
    response get(std::string_view path, headers hdrs = {}) {
        return perform(request{path, method::get, std::move(hdrs)});
    }
};

/// Perform a HTTP request.
response perform(url&& uri, method meth, usz max_redirects);

/// Perform a HTTP request.
inline response perform(std::string_view url_raw, method meth, usz max_redirects) {
    return perform(url{url_raw}, meth, max_redirects);
}

/// Perform a GET request.
inline response get(std::string_view url_raw, usz max_redirects = 10) {
    return perform(url{url_raw}, method::get, max_redirects);
}
} // namespace net::http

namespace net::https {
using client = http::client<net::ssl::client, 443>;
using http::get;
} // namespace net::https

#endif // NET_HTTP_HH
