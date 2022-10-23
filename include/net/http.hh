#ifndef NET_HTTP_HH
#define NET_HTTP_HH

#include "ssl.hh"
#include "utils.hh"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <utility>

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
using octets = std::vector<u8>;

/// HTTP response.
struct response {
    headers hdrs;
    octets body;
    u32 proto{};
    u32 status{};

    response& expect(u32 code) {
        if (status != code) throw std::runtime_error(fmt::format("Expected status {}, but was {}", code, status));
        return *this;
    }
};

struct url {
    std::string host;
    std::string path;
    std::string fragment;
    smap_impl<false> params;
    u16 port{};

    url() {}
    url(std::string_view);
};

/// HTTP request.
struct request {
    url uri;
    method meth;
    headers hdrs;
    octets body;
    u32 proto{};

    /// Create a request.
    explicit request() {}
    explicit request(url uri, headers hdrs = {})
        : uri(std::move(uri)),
          hdrs(std::move(hdrs)) {}

    /// Send the request over a connexion.
    template <typename conn_t>
    void send(conn_t& conn) {
        std::string buf = fmt::format("GET {} HTTP/1.1\r\n", uri.path);
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
        fmt::print("Sending request:\n{}\n", buf);
        conn.send(buf);
    }
};

namespace detail {
constexpr inline bool F = false;
constexpr inline bool T = true;
constexpr inline const bool charmap_tchar[128] = {
    // clang-format off
    F,F,F,F,F,F,F,F,F,F,
    F,F,F,F,F,F,F,F,F,F,
    F,F,F,F,F,F,F,F,F,F,
    F,F,F,T /*'!'*/,T /*'\"'*/,T /*'#'*/,T /*'$'*/,T /*'%'*/,T /*'&'*/,T /*'\''*/,
    F,F,T /*'*'*/,T /*'+'*/,F,T /*'-'*/,T /*'.'*/,F,T /*'0'*/,T /*'1'*/,
    T /*'2'*/,T /*'3'*/,T /*'4'*/,T /*'5'*/,T /*'6'*/,T /*'7'*/,T /*'8'*/,T /*'9'*/,F,F,
    F,F,F,F,F,T /*'A'*/,T /*'B'*/,T /*'C'*/,T /*'D'*/,T /*'E'*/,
    T /*'F'*/,T /*'G'*/,T /*'H'*/,T /*'I'*/,T /*'J'*/,T /*'K'*/,T /*'L'*/,T /*'M'*/,T /*'N'*/,T /*'O'*/,
    T /*'P'*/,T /*'Q'*/,T /*'R'*/,T /*'S'*/,T /*'T'*/,T /*'U'*/,T /*'V'*/,T /*'W'*/,T /*'X'*/,T /*'Y'*/,
    T /*'Z'*/,F,F,F,T /*'^'*/,T /*'_'*/,T /*'`'*/,T /*'a'*/,T /*'b'*/,T /*'c'*/,
    T /*'d'*/,T /*'e'*/,T /*'f'*/,T /*'g'*/,T /*'h'*/,T /*'i'*/,T /*'j'*/,T /*'k'*/,T /*'l'*/,T /*'m'*/,
    T /*'n'*/,T /*'o'*/,T /*'p'*/,T /*'q'*/,T /*'r'*/,T /*'s'*/,T /*'t'*/,T /*'u'*/,T /*'v'*/,T /*'w'*/,
    T /*'x'*/,T /*'y'*/,T /*'z'*/,F,T /*'|'*/,F,T /*'~'*/,F,
};

constexpr inline const char charmap_vchar[128] = {
	F,F,F,F,F,F,F,F,F,F,
	F,F,F,F,F,F,F,F,F,F,
	F,F,F,F,F,F,F,F,F,F,
	F,F,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,F,
};

constexpr inline const unsigned char charmap_text[256] = {
	F,F,F,F,F,F,F,F,F,F,
	F,F,F,F,F,F,F,F,F,F,
	F,F,F,F,F,F,F,F,F,F,
	F,F,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,F,

	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T
};

constexpr inline const bool charmap_uri[128] = {
	F,F,F,F,F,F,F,F,F,F,
	F,F,F,F,F,F,F,F,F,F,
	F,F,F,F,F,F,F,F,F,F,
	F,F,F,T,F,T,T,F,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	F,T,F,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,F,T,F,T,F,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,T,T,T,T,T,T,T,
	T,T,T,F,F,F,T,F,
}; // clang-format on

/// See RFC 7230.
constexpr inline bool istchar(char c) {
    return uint8_t(c) < 128 and charmap_tchar[uint8_t(c)];
}

/// See RFC 7230.
constexpr inline bool isvchar(char c) {
    return uint8_t(c) < 128 and charmap_vchar[uint8_t(c)];
}

/// See RFC 7230.
constexpr inline bool istext(unsigned char c) {
    return charmap_text[c];
}

/// See RFC 7230.
constexpr inline bool isurichar(char c) {
    return uint8_t(c) < 128 and charmap_uri[uint8_t(c)];
}

inline i8 xtonum(char c) {
    if (c >= '0' and c <= '9') return static_cast<i8>(c - '0');
    else if (c >= 'A' and c <= 'F') return static_cast<i8>(c - 'A') + 10;
    else if (c >= 'a' and c <= 'f') return static_cast<i8>(c - 'a') + 10;
    else return -1;
}

/// Define a label.
#define L(name) \
name:

/// Move to next character and jump to a label; if we're at the end of the input, suspend.
#define jmp(l)                                                      \
    do {                                                            \
        i++;                                                        \
        if (data + i >= end) [[unlikely]] {                         \
            consumed += i;                                          \
            do {                                                    \
                YIELD_INCOMPLETE();                                 \
                data = reinterpret_cast<const char*>(input.data()); \
                end = data + input.size();                          \
            } while (data == end);                                  \
        }                                                           \
        goto l;                                                     \
    } while (0)

#define accept()       \
    do {               \
        i++;           \
        goto l_accept; \
    } while (0)

/// Return an error.
#define ERR(...) throw std::runtime_error(fmt::format(__VA_ARGS__))

/// Handle the first character in a percent encoding.
#define PERC_FST(return_state)               \
    do {                                     \
        fst = xtonum(data[i]);               \
        if (fst < 0) [[unlikely]]            \
            ERR("Invalid percent encoding"); \
        jmp(return_state);                   \
    } while (0)

/// Handle the second character in a percent encoding.
#define PERC_SND(return_state, buf)          \
    do {                                     \
        i8 snd = xtonum(data[i]);            \
        if (snd < 0) [[unlikely]]            \
            ERR("Invalid percent encoding"); \
        buf += char(fst * 16 + snd);         \
        jmp(return_state);                   \
    } while (0)

/// Delegate to another parser.
#define DELEGATE(func, ...)                                 \
    do {                                                    \
        input = input.subspan(i);                           \
        auto parse = func(__VA_ARGS__);                     \
        while (not parse()) YIELD_INCOMPLETE();             \
        data = reinterpret_cast<const char*>(input.data()); \
        end = data + input.size();                          \
    } while (0)

/// URI parser.
///
/// Currently, this can only parse the path, query parameters, and fragment of a URI.
///
/// TODO: Make sure this complies with RFC 3986.
template <bool incremental = true>
resumable parse_uri(std::span<const u8> input, u64& consumed, url& uri) {
    /// Parse the request/status line.
    std::string parse_buffer1;
    std::string parse_buffer2;
    const char* data = reinterpret_cast<const char*>(input.data());
    const char* end = data + input.size();
    u64 i = 0;
    u64 start;
    u8 fst;

    /// Make sure there is data to parse.
    while (data == end) {
        if constexpr (not incremental) ERR("Unexpected end of input");
        YIELD_INCOMPLETE();
        data = reinterpret_cast<const char*>(input.data());
        end = data + input.size();
    }

/// Create a URI and return.
#define MK_URI(return_state)                                       \
    do {                                                           \
        uri.path = std::string_view{data + start, u64(i - start)}; \
        jmp(return_state);                                         \
    } while (0)

    /// URI parser.
    L (l_uri_path_init) { start = i; /** fallthrough **/ }
    L (l_uri_path) {
        switch (data[i]) {
            case '?': MK_URI(l_uri_param_name_init);
            case '%':
                parse_buffer1.append(data + start, u64(i - start));
                jmp(l_uri_path_percent);
            case ' ': MK_URI(l_accept);
            case '#': MK_URI(l_uri_fragment_init);
            default:
                if (not isurichar(data[i]))
                    ERR("Invalid character in URI: '{}'", data[i]);
                [[fallthrough]];
            case '/':
                if constexpr (incremental) {
                    jmp(l_uri_path);
                } else {
                    i++;
                    if (data + i >= end) [[unlikely]] {
                        uri.path = std::string_view{data + start, u64(i - start)};
                        goto l_accept;
                    }
                    goto l_uri_path;
                }
        }
    }

    /// Parse a percent-encoded character in a URI path.
    L (l_uri_path_percent) { PERC_FST(l_uri_path_percent_2); }
    L (l_uri_path_percent_2) { PERC_SND(l_uri_path_init, parse_buffer1); }

    /// URI param name.
    L (l_uri_param_name_init) { start = i; /** fallthrough **/ }
    L (l_uri_param_name) {
        switch (data[i]) {
            case '=':
                parse_buffer1.append(data + start, u64(i - start));
                jmp(l_uri_param_val_init);
            case '&':
                parse_buffer1.append(data + start, u64(i - start));
                if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = "";
                parse_buffer1.clear();
                jmp(l_uri_param_name_init);
            case '%':
                parse_buffer1.append(data + start, u64(i - start));
                jmp(l_uri_param_name_percent);
            case ' ':
                parse_buffer1.append(data + start, u64(i - start));
                if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = "";
                accept();
            case '#':
                parse_buffer1.append(data + start, u64(i - start));
                if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = "";
                jmp(l_uri_fragment_init);
            default:
                if (not isurichar(data[i])) ERR("Invalid character in URI param name: {}", data[i]);
                if constexpr (incremental) {
                    jmp(l_uri_param_name);
                } else {
                    i++;
                    if (data + i >= end) [[unlikely]] {
                        parse_buffer1.append(data + start, u64(i - start));
                        if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = "";
                        goto l_accept;
                    }
                    goto l_uri_param_name;
                }
        }
    }

    /// Parse a percent-encoded character in a URI param name.
    L (l_uri_param_name_percent) { PERC_FST(l_uri_param_name_percent_2); }
    L (l_uri_param_name_percent_2) { PERC_SND(l_uri_param_name_init, parse_buffer1); }

    /// URI param value.
    L (l_uri_param_val_init) { start = i; /** fallthrough **/ }
    L (l_uri_param_val) {
        switch (data[i]) {
            case '&':
                parse_buffer2.append(data + start, u64(i - start));
                if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = parse_buffer2;
                parse_buffer1.clear();
                parse_buffer2.clear();
                jmp(l_uri_param_name_init);
            case '%':
                parse_buffer2.append(data + start, u64(i - start));
                jmp(l_uri_param_val_percent);
            case ' ':
                parse_buffer2.append(data + start, u64(i - start));
                if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = parse_buffer2;
                accept();
            case '#':
                parse_buffer2.append(data + start, u64(i - start));
                if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = parse_buffer2;
                jmp(l_uri_fragment_init);
            default:
                if (not isurichar(data[i])) ERR("Invalid character in URI param value: {}", data[i]);
                if constexpr (incremental) {
                    jmp(l_uri_param_val);
                } else {
                    i++;
                    if (data + i >= end) [[unlikely]] {
                        parse_buffer2.append(data + start, u64(i - start));
                        if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = parse_buffer2;
                        goto l_accept;
                    }
                    goto l_uri_param_val;
                }
        }
    }

    /// Parse a percent-encoded character in a URI param value.
    L (l_uri_param_val_percent) { PERC_FST(l_uri_param_val_percent_2); }
    L (l_uri_param_val_percent_2) { PERC_SND(l_uri_param_val_init, parse_buffer2); }

    /// URI fragment.
    L (l_uri_fragment_init) {
        start = i;
        parse_buffer1.clear(); /** fallthrough **/
    }
    L (l_uri_fragment) {
        switch (data[i]) {
            case '%':
                parse_buffer1.append(data + start, i - start);
                jmp(l_uri_fragment_percent);
            case ' ':
                parse_buffer1.append(data + start, i - start);
                uri.fragment = parse_buffer1;
                accept(); /** Not uri chars. **/
            case '?':
            case '/':
                jmp(l_uri_fragment);
            default:
                if (not isurichar(data[i])) ERR("Invalid character in URI fragment: {}", data[i]);
                if constexpr (incremental) {
                    jmp(l_uri_fragment);
                } else {
                    i++;
                    if (data + i >= end) [[unlikely]] {
                        parse_buffer1.append(data + start, i - start);
                        uri.fragment = parse_buffer1;
                        goto l_accept;
                    }
                    goto l_uri_fragment;
                }
        }
    }

    /// Parse a percent-encoded character in a URI fragment.
    L (l_uri_fragment_percent) { PERC_FST(l_uri_fragment_percent_2); }
    L (l_uri_fragment_percent_2) { PERC_SND(l_uri_fragment_init, parse_buffer1); }

    /// Done!
    L (l_accept) {
        consumed += i;
        YIELD_SUCCESS();
    }

#undef MK_URI
}

/// HTTP headers parser.
///
/// This parses HTTP headers and the final CRLF that terminates them.
resumable parse_headers(std::span<const u8>& input, u64& consumed, headers& hdrs) {
    /// Parse the request/status line.
    std::string name;
    const char* data = reinterpret_cast<const char*>(input.data());
    const char* end = data + input.size();
    u64 i = 0;
    u64 start;

    /// Make sure there is data to parse.
    while (data == end) {
        YIELD_INCOMPLETE();
        data = reinterpret_cast<const char*>(input.data());
        end = data + input.size();
    }

    /// Helper to add a header to the request.
    const auto append_header = [&]() {
        std::ranges::transform(name.begin(), name.end(), name.begin(), [](auto c) { return std::tolower(c); });
        hdrs[name] = std::string_view{data + start, i - start};
        name.clear();
    };

    /// Actual parser.
    L (l_start) {
        start = i;
        switch (data[i]) {
            case '\r': jmp(l_needs_final_lf);
            case '\n': accept();
            default:
                if (not istchar(data[i])) ERR("Invalid character in header name: {}", data[i]);
                jmp(l_name);
        }
    }

    /// Header name.
    L (l_name) {
        switch (data[i]) {
            case '\r': jmp(l_needs_lf);
            case '\n': jmp(l_start);
            case ':':
                name.append(data + start, i - start);
                jmp(l_colon);
            default:
                if (not istchar(data[i])) ERR("Invalid character in header name: {}", data[i]);
                jmp(l_name);
        }
    }

    /// Colon and whitespace.
    L (l_colon) { start = i; /** fallthrough **/ }
    L (l_ws_after_colon) {
        switch (data[i]) {
            case ' ':
            case '\t': jmp(l_ws_after_colon);
            default:
                if (istext(data[i])) {
                    start = i;
                    jmp(l_value);
                }
                ERR("Invalid character after colon in header: {}", data[i]);
        }
    }

    /// Header value.
    L (l_value) {
        switch (data[i]) {
            case ' ':
            case '\t': jmp(l_ws_after_value);
            case '\r':
                append_header();
                jmp(l_needs_lf);
            case '\n':
                append_header();
                jmp(l_start);
            default:
                if (not istext(data[i])) ERR("Invalid character in header value: {}", data[i]);
                jmp(l_value);
        }
    }

    /// Whitespace after the value.
    L (l_ws_after_value) {
        switch (data[i]) {
            case ' ':
            case '\t': jmp(l_ws_after_value);
            case '\r':
                append_header();
                jmp(l_needs_lf);
            case '\n':
                append_header();
                jmp(l_start);
            default:
                if (istext(data[i])) jmp(l_value);
                ERR("Invalid character in header after value: {}", data[i]);
        }
    }

    /// LF after header value.
    L (l_needs_lf) {
        switch (data[i]) {
            case '\n': jmp(l_start);
            default: ERR("Headers: needs LF, got {}", data[i]);
        }
    }

    /// Final CRLF after the headers.
    L (l_needs_final_lf) {
        switch (data[i]) {
            case '\n': accept();
            default: ERR("Headers: needs final LF, got {}", data[i]);
        }
    }

    /// Done!
    L (l_accept) {
        consumed += i;
        YIELD_SUCCESS();
    }
}

/// HTTP request parser.
///
/// \param input The input buffer.
/// \param consumed How many characters have been consumed from the input buffer.
/// \param req The output request.
resumable parse_request(std::span<const u8>& input, u64& consumed, request& req) {
    /// Parse the request/status line.
    const char* data = reinterpret_cast<const char*>(input.data());
    const char* end = data + input.size();
    u64 i = 0;
    u64 start;

    /// Make sure there is data to parse.
    while (data == end) {
        YIELD_INCOMPLETE();
        data = reinterpret_cast<const char*>(input.data());
        end = data + input.size();
    }

    /// Parser entry point.

    L (l_ws_after_uri) {
        switch (data[i]) {
            case ' ': jmp(l_ws_after_uri);
            case '\r':
                req.proto = 9;
                jmp(l_needs_lf);
            case '\n':
                /// HTTP/0.9 doesn't have headers.
                req.proto = 9;
                accept();
            case 'H': jmp(l_H);
            default: ERR("Invalid character after URI: {}", data[i]);
        }
    }

    /// Parser entry point.
    L (l_start) {
        start = i;

        /// Requests may be preceded by CRLF for some reason...
        if (data[i] == '\r' or data[i] == '\n') jmp(l_start);
        jmp(l_method);
    }

    /// Parse the method.
    L (l_method) {
        /// Whitespace after the method.
        if (data[i] == ' ') {
            switch (i - start) {
                case 3:
                    if (std::memcmp(data + start, "GET ", 4) == 0) [[likely]] {
                        req.meth = method::get;
                        jmp(l_ws_after_method);
                    }
                    ERR("Method not supported");
                case 4:
                    if (std::memcmp(data + start, "HEAD", 4) == 0) {
                        req.meth = method::head;
                        jmp(l_ws_after_method);
                    } else if (std::memcmp(data + start, "POST", 4) == 0) {
                        req.meth = method::post;
                        jmp(l_ws_after_method);
                    }
                    [[fallthrough]];
                default:
                    ERR("Method not supported");
            }
        }
        if (data[i] < 'A' or data[i] > 'Z') ERR("Invalid character in method name: '{}'", data[i]);
    }

    L (l_ws_after_method) {
        switch (data[i]) {
            case ' ': jmp(l_ws_after_method);
            case '/': {
                /// Call the URI parser.
                DELEGATE(parse_uri, input, i, req.uri);
                jmp(l_ws_after_uri);
            }
            default: ERR("Invalid character after method name: '{}'", data[i]);
        }
    }

    L (l_H) {
        if (data[i] == 'T') jmp(l_HT);
        ERR("Expected T after H, got {}", data[i]);
    }

    L (l_HT) {
        if (data[i] == 'T') jmp(l_HTT);
        ERR("Expected T after HT, got {}", data[i]);
    }

    L (l_HTT) {
        if (data[i] == 'P') jmp(l_HTTP);
        ERR("Expected P after HTT, got {}", data[i]);
    }

    L (l_HTTP) {
        if (data[i] == '/') jmp(l_http_ver_maj);
        ERR("Expected / after HTTP, got {}", data[i]);
    }

    L (l_http_ver_maj) {
        switch (data[i]) {
            case '0': jmp(l_http_ver_maj);
            case '1': jmp(l_http_ver_rest);
            case '2' ... '9': ERR("Unsupported http major version: {}", data[i] - '0');
            default: ERR("Expected major version after HTTP/, got {}", data[i]);
        }
    }

    L (l_http_ver_rest) {
        if (data[i] == '.') jmp(l_http_ver_min);
        ERR("Expected . in protocol version, got {}", data[i]);
    }

    L (l_http_ver_min) {
        switch (data[i]) {
            case '0':
                req.proto = 10;
                jmp(l_ws_after_ver);
            case '1':
                req.proto = 11;
                jmp(l_ws_after_ver);
            case '\r': jmp(l_needs_lf);
            case '\n':

            case ' ': jmp(l_ws_after_ver);
            case '2' ... '9': ERR("Unsupported http minor version: {}", data[i] - '0');
            default: ERR("Invalid character in protocol version: {}", data[i]);
        }
    }

    L (l_ws_after_ver) {
        switch (data[i]) {
            case ' ': jmp(l_ws_after_ver);
            case '\n':
                i++;
                DELEGATE(parse_headers, input, i, req.hdrs);
                accept();
            case '\r': jmp(l_needs_lf);
            default: ERR("Invalid character in whitespace after protocol version: {}", data[i]);
        }
    }

    L (l_needs_lf) {
        if (data[i] == '\n') {
            i++;
            DELEGATE(parse_headers, input, i, req.hdrs);
            accept();
        }
        ERR("Expected LF, got {}", data[i]);
    }

    /// Done!
    L (l_accept) {
        consumed += i;
        YIELD_SUCCESS();
    }
}

/// HTTP response parser.
///
/// \param input The input buffer.
/// \param consumed How many characters have been consumed from the input buffer.
/// \param res The output response.
resumable parse_response(std::span<const u8>& input, u64& consumed, response& res) {
    /// Parse the request/status line.
    const char* data = reinterpret_cast<const char*>(input.data());
    const char* end = data + input.size();
    u64 i = 0;

    /// Make sure there is data to parse.
    while (data == end) {
        YIELD_INCOMPLETE();
        data = reinterpret_cast<const char*>(input.data());
        end = data + input.size();
    }

    L (l_ws_after_uri) {
        switch (data[i]) {
            case ' ': jmp(l_ws_after_uri);
            case '\r':
                res.proto = 9;
                jmp(l_needs_lf);
            case '\n':
                /// HTTP/0.9 doesn't have headers.
                res.proto = 9;
                accept();
            case 'H': jmp(l_H);
            default: ERR("Invalid character after URI: '{}'", data[i]);
        }
    }

    /// Parser entry point.
    L (l_start) {
        if (data[i] == 'H') jmp(l_H);
        ERR("Expected HTTP version in status line");
    }

    L (l_H) {
        if (data[i] == 'T') jmp(l_HT);
        ERR("Expected T after H, got {}", data[i]);
    }

    L (l_HT) {
        if (data[i] == 'T') jmp(l_HTT);
        ERR("Expected T after HT, got {}", data[i]);
    }

    L (l_HTT) {
        if (data[i] == 'P') jmp(l_HTTP);
        ERR("Expected P after HTT, got {}", data[i]);
    }

    L (l_HTTP) {
        if (data[i] == '/') jmp(l_http_ver_maj);
        ERR("Expected / after HTTP, got {}", data[i]);
    }

    L (l_http_ver_maj) {
        switch (data[i]) {
            case '0': jmp(l_http_ver_maj);
            case '1': jmp(l_http_ver_rest);
            case '2' ... '9': ERR("Unsupported http major version: {}", data[i] - '0');
            default: ERR("Expected major version after HTTP/, got {}", data[i]);
        }
    }

    L (l_http_ver_rest) {
        if (data[i] == '.') jmp(l_http_ver_min);
        ERR("Expected . in protocol version, got {}", data[i]);
    }

    L (l_http_ver_min) {
        switch (data[i]) {
            case '0':
                res.proto = 10;
                jmp(l_ws_after_ver);
            case '1':
                res.proto = 11;
                jmp(l_ws_after_ver);
            case '\r': jmp(l_needs_lf);
            case '\n':
                i++;
                DELEGATE(parse_headers, input, i, res.hdrs);
                accept();
            case ' ': jmp(l_ws_after_ver);
            case '2' ... '9': ERR("Unsupported http minor version: {}", data[i] - '0');
            default: ERR("Invalid character in protocol version: {}", data[i]);
        }
    }

    L (l_ws_after_ver) {
        switch (data[i]) {
            case ' ': jmp(l_ws_after_ver);
            default:
                if (std::isdigit(data[i])) {
                    res.status = (data[i] - '0') * 100;
                    jmp(l_status_2nd);
                }
                ERR("Invalid character in whitespace after protocol version: {}", data[i]);
        }
    }

    L (l_status_2nd) {
        if (std::isdigit(data[i])) {
            res.status += (data[i] - '0') * 10;
            jmp(l_status_3rd);
        }
        ERR("Status code may only contain digits");
    }

    L (l_status_3rd) {
        if (std::isdigit(data[i])) {
            res.status += (data[i] - '0');
            jmp(l_first_ws_after_status);
        }
        ERR("Status code may only contain digits");
    }

    L (l_first_ws_after_status) {
        switch (data[i]) {
            case ' ': jmp(l_ws_after_status);
            case '\r': jmp(l_needs_lf);
            case '\n':
                i++;
                DELEGATE(parse_headers, input, i, res.hdrs);
                accept();
            default: ERR("Invalid character after status code: {}", data[i]);
        }
    }

    L (l_ws_after_status) {
        switch (data[i]) {
            case ' ': jmp(l_ws_after_status);
            case '\r': jmp(l_needs_lf);
            case '\n':
                i++;
                DELEGATE(parse_headers, input, i, res.hdrs);
                accept();
            default: goto l_reason_phrase; /// (!)
        }
    }

    L (l_reason_phrase) {
        if (not istext(data[i])) {
            if (data[i] == '\r') jmp(l_needs_lf);
            if (data[i] == '\n') {
                i++;
                DELEGATE(parse_headers, input, i, res.hdrs);
                accept();
            }
            ERR("Reason phrase contains invalid character: '{}'", data[i]);
        }
        jmp(l_reason_phrase);
    }

    L (l_needs_lf) {
        if (data[i] == '\n') {
            i++;
            DELEGATE(parse_headers, input, i, res.hdrs);
            accept();
        }
        ERR("Expected LF, got {}", data[i]);
    }

    /// Done!
    L (l_accept) {
        consumed += i;
        YIELD_SUCCESS();
    }
}

#undef L
#undef jmp
#undef ERR
#undef accept
#undef PERC_FST
#undef PERC_SND
#undef DELEGATE
} // namespace detail

/// Parse a url.
url::url(std::string_view sv) {
    /// Parse the url.
    u64 consumed = 0;
    auto parser = detail::parse_uri<false>(
        std::span<const u8>{reinterpret_cast<const u8*>(sv.data()), sv.size()},
        consumed,
        *this
    );
    if (not parser() or consumed != sv.size())
        throw std::runtime_error("Not a valid URL");
}

template <typename backend_t = tcp::client, u16 default_port = 80>
struct client {
protected:
    using backend_type = backend_t;
    recvbuffer buffer;
    backend_type conn;

public:
    explicit client() : conn() {}
    explicit client(std::string_view host_name, u16 port = default_port) : conn(host_name, port) {}

    /// Perform a request.
    ///
    /// \param req The request to perform.
    /// \param us_timeout How long to wait for a response (in microseconds).
    ///     A value of 0 means no timeout.
    /// \throw std::runtime_error If the request fails or if the response is invalid.
    /// \return The response.
    response perform(request&& req, chrono::microseconds us_timeout = 1s) {
        if (us_timeout < 0us) throw std::runtime_error("Timeout must be positive");

        /// Send the request.
        req.hdrs["Host"] = conn.host();
        if (not req.hdrs.has("Connection")) req.hdrs["Connection"] = "keep-alive";
        req.send(conn);

        /// Read the response.
        auto res = response{};
        auto now = chrono::high_resolution_clock::now();

        /// TODO: recv in separate thread w/ std::async and std::future to allow for timeouts.
        /// Create a parser.
        std::span<const u8> span;
        u64 consumed = 0;
        auto parser = detail::parse_response(span, consumed, res);
        for (;;) {
            /// Allocate space in the buffer.
            static constexpr u64 increment = 1024;
            buffer.allocate(increment);

            /// Receive data.
            conn.recv(buffer);
            if (buffer.empty()) throw std::runtime_error("Connection closed by peer");

            /// Update the span.
            span = buffer.span();

            /// Advance the parser.
            auto done = parser();
            buffer.skip(consumed);

            /// Stop if we're done.
            if (done) break;

            /// Check if the timeout has been reached.
            if (us_timeout > 0us and chrono::high_resolution_clock::now() - now > us_timeout)
                throw std::runtime_error("Timeout reached");
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
        return perform(request{std::move(url), std::move(hdrs)});
    }

    /// Perform a GET request.
    ///
    /// \param path The path to GET.
    /// \param hdrs The headers to send.
    /// \return The response.
    response get(std::string_view path, headers hdrs = {}) {
        return perform(request{path, std::move(hdrs)});
    }
};

/// Perform a GET request.
inline response get(std::string_view url) {
    return url.starts_with("https")
               ? client<net::ssl::client>().get(url, {{"Connection", "close"}})
               : client<net::tcp::client>().get(url, {{"Connection", "close"}});
}

} // namespace net::http

namespace net::https {
using client = http::client<net::ssl::client, 443>;
} // namespace net::https

#endif // NET_HTTP_HH
