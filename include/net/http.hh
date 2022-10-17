#ifndef NET_HTTP_HH
#define NET_HTTP_HH

#include "ssl.hh"
#include "utils.hh"

#include <atomic>
#include <mutex>
#include <unordered_map>

namespace net::http {

namespace chrono = std::chrono;
using namespace std::chrono_literals;

/// HTTP Verbs.
enum struct method {
    get,
    head,
    post,
};

/// HTTP headers.
struct smap {
    std::unordered_map<std::string, std::string> values;

    /// Reference to a header value.
    struct smap_ref {
        smap& parent;
        std::string key;

        /// Create a reference to a header value.
        smap_ref(smap& parent, std::string&& key) : parent(parent), key(std::move(key)) {}

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
        std::string_view operator*() { return parent.values.at(key); }
    };

    /// Get a reference to a header value.
    smap_ref operator[](std::string_view key) { return {*this, std::string{key}}; }

    /// Check if there are elements in the map.
    bool empty() const { return values.empty(); }

    /// Check if a certain header exists.
    bool has(const std::string& key) { return values.contains(key); }
};

/// `smap` isn't very expressive.
using headers = smap;

/// HTTP response.
template <typename body_t>
struct response {
    using body_type = body_t;

    headers hdrs;
    body_type body;
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
    smap params;
    u16 port{};

    url() {}
    url(std::string_view);
};

/// HTTP request.
template <typename body_t = std::string>
struct request {
    using body_type = body_t;

    url uri;
    method meth;
    headers hdrs;
    body_type body;
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

/// Parser return code.
enum struct http_parse_result_code {
    success = 1,
    incomplete = 2,
    error = 3,
};

/// Parser return value.
struct http_parse_result {
    http_parse_result_code code;
    std::exception_ptr error;

    http_parse_result() {}
    http_parse_result(http_parse_result_code code, std::exception_ptr e) : code(code), error(e) {}
};

///
/// TODO: The HTTP Parser was supposed to be efficient, but also readable; right
///       now, it is a horrid mess. We should split this into seperate functions,
///       even if that means a bit of code duplication.
///

/// Define a label.
#define L(name) \
name:

#define L_SEC(name, sec) \
    L (name)             \
        SECTION (sec)

/// Declare labels.
#define L_DECLS(...) __label__ __VA_ARGS__

/// This is just to avoid indenting everything by one more level.
#define SECTION(name) if constexpr (is<obj, name<std::vector<char>>> or is<obj, name<std::string>>)

#define DONE (lval == acceptval)

/// Move to next character and jump to a label; if we're at the end of the input, suspend.
#define jmp(l)                                                                               \
    do {                                                                                     \
        i++;                                                                                 \
        static constexpr void* lval = &&l;                                                   \
        static constexpr void* acceptval = &&l_accept;                                       \
        if (data + i == end) [[unlikely]] {                                                  \
            if (not DONE) {                                                                  \
                consumed += i;                                                               \
                do {                                                                         \
                    co_yield http_parse_result{http_parse_result_code::incomplete, nullptr}; \
                    data = input.data();                                                     \
                    end = input.end();                                                       \
                } while (data == end);                                                       \
            } else goto l_accept;                                                            \
        }                                                                                    \
        goto l;                                                                              \
    } while (0)

#define jmp_if_req(l)       \
    do {                    \
        SECTION (request) { \
            jmp(l);         \
        }                   \
    } while (0)
#define jmp_if_res(l)        \
    do {                     \
        SECTION (response) { \
            jmp(l);          \
        }                    \
    } while (0)

/// Return an error.
#define ERR(...)                                                                                                                          \
    do {                                                                                                                                  \
        co_yield http_parse_result{http_parse_result_code::error, std::make_exception_ptr(std::runtime_error(fmt::format(__VA_ARGS__)))}; \
        co_return;                                                                                                                        \
    } while (0)

/// Create a URI.
#define MK_URI(return_state)                                         \
    do {                                                             \
        o.uri.path = std::string_view{data + start, u64(i - start)}; \
        parse_buffer1.clear();                                       \
        jmp(return_state);                                           \
    } while (0)

#define NOT_RES if constexpr (not is<obj, response<std::vector<char>>> and not is<obj, response<std::string>>)

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

#define HTTP_PARSER_INIT() /** Parser state. **/                                 \
    std::string parse_buffer1;                                                   \
    std::string parse_buffer2;                                                   \
    const char* data = input.data();                                             \
    const char* end = data + input.size();                                       \
    u64 i = 0;                                                                   \
    u64 start;                                                                   \
    u8 fst;                                                                      \
                                                                                 \
    /** Make sure there is data to parse. **/                                    \
    while (data == end) {                                                        \
        co_yield http_parse_result{http_parse_result_code::incomplete, nullptr}; \
        data = input.data();                                                     \
        end = input.end();                                                       \
    }

#define HTTP_PARSER_END() /** Should never get here. **/                      \
    UNREACHABLE();                                                            \
                                                                              \
    /** Done! **/                                                             \
    L (l_accept) {                                                            \
        consumed += i;                                                        \
        co_yield http_parse_result{http_parse_result_code::success, nullptr}; \
        co_return;                                                            \
    }

#define URI_PARSER(return_state, MK_URI, URI)                                                                     \
    {                                                                                                             \
        /** Parse the start of a URI. **/                                                                         \
        L (l_uri_path_init) NOT_RES {                                                                             \
                { start = i; /** fallthrough **/ }                                                                \
                L (l_uri_path) {                                                                                  \
                    switch (data[i]) {                                                                            \
                        case '?': MK_URI(l_uri_param_name_init);                                                  \
                        case '%':                                                                                 \
                            parse_buffer1.append(data + start, u64(i - start));                                   \
                            jmp(l_uri_path_percent);                                                              \
                        case ' ': MK_URI(return_state);                                                           \
                        case '#': MK_URI(l_uri_fragment_init);                                                    \
                        default:                                                                                  \
                            if (not isurichar(data[i])) ERR("Invalid character in URI: '{}'", data[i]);           \
                            jmp(l_uri_path);                                                                      \
                    }                                                                                             \
                }                                                                                                 \
                                                                                                                  \
                /** Parse a percent-encoded character in a URI path. **/                                          \
                L (l_uri_path_percent) { PERC_FST(l_uri_path_percent_2); }                                        \
                L (l_uri_path_percent_2) { PERC_SND(l_uri_path_init, parse_buffer1); }                            \
                                                                                                                  \
                /** URI param name. **/                                                                           \
                L (l_uri_param_name_init) { start = i; /** fallthrough **/ }                                      \
                L (l_uri_param_name) {                                                                            \
                    switch (data[i]) {                                                                            \
                        case '=':                                                                                 \
                            parse_buffer1.append(data + start, u64(i - start));                                   \
                            jmp(l_uri_param_val_init);                                                            \
                        case '&':                                                                                 \
                            parse_buffer1.append(data + start, u64(i - start));                                   \
                            if (not URI.params.has(parse_buffer1)) URI.params[parse_buffer1] = "";                \
                            parse_buffer1.clear();                                                                \
                            jmp(l_uri_param_name_init);                                                           \
                        case '%':                                                                                 \
                            parse_buffer1.append(data + start, u64(i - start));                                   \
                            jmp(l_uri_param_name_percent);                                                        \
                        case ' ':                                                                                 \
                            parse_buffer1.append(data + start, u64(i - start));                                   \
                            if (not URI.params.has(parse_buffer1)) URI.params[parse_buffer1] = "";                \
                            jmp(return_state);                                                                    \
                        case '#':                                                                                 \
                            parse_buffer1.append(data + start, u64(i - start));                                   \
                            if (not URI.params.has(parse_buffer1)) URI.params[parse_buffer1] = "";                \
                            jmp(l_uri_fragment_init);                                                             \
                        default:                                                                                  \
                            if (not isurichar(data[i])) ERR("Invalid character in URI param name: {}", data[i]);  \
                            jmp(l_uri_param_name);                                                                \
                    }                                                                                             \
                }                                                                                                 \
                                                                                                                  \
                /** Parse a percent-encoded character in a URI param name. **/                                    \
                L (l_uri_param_name_percent) { PERC_FST(l_uri_param_name_percent_2); }                            \
                L (l_uri_param_name_percent_2) { PERC_SND(l_uri_param_name_init, parse_buffer1); }                \
                                                                                                                  \
                /** URI param value. **/                                                                          \
                L (l_uri_param_val_init) { start = i; /** fallthrough **/ }                                       \
                L (l_uri_param_val) {                                                                             \
                    switch (data[i]) {                                                                            \
                        case '&':                                                                                 \
                            parse_buffer2.append(data + start, u64(i - start));                                   \
                            if (auto str = parse_buffer1; not URI.params.has(str))                                \
                                URI.params[str] = parse_buffer2;                                                  \
                            parse_buffer1.clear();                                                                \
                            parse_buffer2.clear();                                                                \
                            jmp(l_uri_param_name_init);                                                           \
                        case '%':                                                                                 \
                            parse_buffer2.append(data + start, u64(i - start));                                   \
                            jmp(l_uri_param_val_percent);                                                         \
                        case ' ':                                                                                 \
                            parse_buffer2.append(data + start, u64(i - start));                                   \
                            if (auto str = parse_buffer1; not URI.params.has(str))                                \
                                URI.params[str] = parse_buffer2;                                                  \
                            jmp(return_state);                                                                    \
                        case '#':                                                                                 \
                            parse_buffer2.append(data + start, u64(i - start));                                   \
                            if (auto str = parse_buffer1; not URI.params.has(str))                                \
                                URI.params[str] = parse_buffer2;                                                  \
                            jmp(l_uri_fragment_init);                                                             \
                        default:                                                                                  \
                            if (not isurichar(data[i])) ERR("Invalid character in URI param value: {}", data[i]); \
                            jmp(l_uri_param_val);                                                                 \
                    }                                                                                             \
                }                                                                                                 \
                                                                                                                  \
                /** Parse a percent-encoded character in a URI param value. **/                                   \
                L (l_uri_param_val_percent) { PERC_FST(l_uri_param_val_percent_2); }                              \
                L (l_uri_param_val_percent_2) { PERC_SND(l_uri_param_val_init, parse_buffer2); }                  \
                                                                                                                  \
                /** URI fragment. **/                                                                             \
                L (l_uri_fragment_init) {                                                                         \
                    start = i;                                                                                    \
                    parse_buffer1.clear();                                                                        \
                    /** fallthrough **/                                                                           \
                }                                                                                                 \
                L (l_uri_fragment) {                                                                              \
                    switch (data[i]) {                                                                            \
                        case '%':                                                                                 \
                            parse_buffer1.append(data + start, i - start);                                        \
                            jmp(l_uri_fragment_percent);                                                          \
                        case ' ':                                                                                 \
                            parse_buffer1.append(data + start, i - start);                                        \
                            URI.fragment = parse_buffer1;                                                         \
                            jmp(return_state);                                                                    \
                            /** Not uri chars. **/                                                                \
                        case '?':                                                                                 \
                        case '/':                                                                                 \
                            jmp(l_uri_fragment);                                                                  \
                        default:                                                                                  \
                            if (not isurichar(data[i])) ERR("Invalid character in URI fragment: {}", data[i]);    \
                            jmp(l_uri_fragment);                                                                  \
                    }                                                                                             \
                }                                                                                                 \
                                                                                                                  \
                /** Parse a percent-encoded character in a URI fragment. **/                                      \
                L (l_uri_fragment_percent) { PERC_FST(l_uri_fragment_percent_2); }                                \
                L (l_uri_fragment_percent_2) { PERC_SND(l_uri_fragment_init, parse_buffer1); }                    \
            }                                                                                                     \
    }

/// HTTP request/response parser.
///
/// For the sake of your own sanity, please refrain from invoking this function directly.
/// It is fairly complicated for performance reasons, and requires setup from the caller
/// to make sure the parser state is handled correctly.
///
/// This function never throws an exception. If an exception is thrown during parsing,
/// it is stored in the result and can be rethrown by the caller.
///
/// \tparam obj The type of the object that we want to parse.
/// \param input The input buffer.
/// \param consumed How many characters have been consumed from the input buffer.
/// \param o The output object.
template <typename obj = request<std::string>>
co_generator<http_parse_result> parser(std::string_view& input, u64& consumed, obj& o) noexcept {
    /// Parse the request/status line.
    HTTP_PARSER_INIT()
    L (l_start_line) {
        L_DECLS(
            l_start, l_method, l_ws_after_method,
            l_ws_after_uri,
            l_status_2nd, l_status_3rd, l_first_ws_after_status,
            l_ws_after_status, l_reason_phrase,
            l_H, l_HT, l_HTT, l_HTTP, l_http_ver_maj, l_http_ver_rest,
            l_http_ver_min, l_ws_after_ver, l_needs_lf
        );

        /// URI parser.
        URI_PARSER(l_ws_after_uri, MK_URI, o.uri)
        L (l_ws_after_uri) {
            switch (data[i]) {
                case ' ': jmp(l_ws_after_uri);
                case '\r':
                    o.proto = 9;
                    jmp(l_needs_lf);
                case '\n':
                    o.proto = 9;
                    jmp(l_headers);
                case 'H': jmp(l_H);
                default: ERR("Invalid character after URI: {}", data[i]);
            }
        }

        /// Parser entry point.
        L (l_start) {
            start = i;

            /// Requests may be preceded by CRLF for some reason...
            SECTION (request) {
                if (data[i] == '\r' or data[i] == '\n') jmp(l_start);
                jmp(l_method);
            }

            /// The status line of a response is much simpler.
            SECTION (response) {
                if (data[i] == 'H') jmp(l_H);
                ERR("Expected HTTP version in status line");
            }
        }

        /// Parse the method.
        L_SEC (l_method, request) {
            /// Whitespace after the method.
            if (data[i] == ' ') {
                switch (i - start) {
                    case 3:
                        if (std::memcmp(data + start, "GET ", 4) == 0) [[likely]] {
                            o.meth = method::get;
                            jmp(l_ws_after_method);
                        }
                        ERR("Method not supported");
                    case 4:
                        if (std::memcmp(data + start, "HEAD", 4) == 0) {
                            o.meth = method::head;
                            jmp(l_ws_after_method);
                        } else if (std::memcmp(data + start, "POST", 4) == 0) {
                            o.meth = method::post;
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
                case '/': jmp(l_uri_path_init);
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
                    o.proto = 10;
                    jmp(l_ws_after_ver);
                case '1':
                    o.proto = 11;
                    jmp(l_ws_after_ver);
                case '\r': jmp(l_needs_lf);
                case '\n': jmp(l_headers);
                case ' ': jmp(l_ws_after_ver);
                case '2' ... '9': ERR("Unsupported http minor version: {}", data[i] - '0');
                default: ERR("Invalid character in protocol version: {}", data[i]);
            }
        }

        L (l_ws_after_ver) {
            switch (data[i]) {
                case ' ': jmp(l_ws_after_ver);
                case '\n': jmp_if_req(l_headers); [[fallthrough]];
                case '\r': jmp_if_req(l_needs_lf); [[fallthrough]];
                default:
                    SECTION (response) {
                        if (std::isdigit(data[i])) {
                            o.status = (data[i] - '0') * 100;
                            jmp(l_status_2nd);
                        }
                    }
                    ERR("Invalid character in whitespace after protocol version: {}", data[i]);
            }
        }

        L_SEC (l_status_2nd, response) {
            if (std::isdigit(data[i])) {
                o.status += (data[i] - '0') * 10;
                jmp(l_status_3rd);
            }
            ERR("Status code may only contain digits");
        }

        L_SEC (l_status_3rd, response) {
            if (std::isdigit(data[i])) {
                o.status += (data[i] - '0');
                jmp(l_first_ws_after_status);
            }
            ERR("Status code may only contain digits");
        }

        L_SEC (l_first_ws_after_status, response) {
            switch (data[i]) {
                case ' ': jmp(l_ws_after_status);
                case '\r': jmp(l_needs_lf);
                case '\n': jmp(l_headers);
                default: ERR("Invalid character after status code: {}", data[i]);
            }
        }

        L_SEC (l_ws_after_status, response) {
            switch (data[i]) {
                case ' ': jmp(l_ws_after_status);
                case '\r': jmp(l_needs_lf);
                case '\n': jmp(l_headers);
                default: goto l_reason_phrase; /// (!)
            }
        }

        L_SEC (l_reason_phrase, response) {
            if (not istext(data[i])) {
                if (data[i] == '\r') jmp(l_needs_lf);
                if (data[i] == '\n') jmp(l_headers);
                ERR("Reason phrase contains invalid character: '{}'", data[i]);
            }
            jmp(l_reason_phrase);
        }

        L (l_needs_lf) {
            if (data[i] == '\n') jmp(l_headers);
            ERR("Expected LF, got {}", data[i]);
        }
    }

    /// Should never get here.
    UNREACHABLE();

    /// Parse headers entry point.
    L (l_headers) {
        L_DECLS(
            l_start, l_name, l_colon, l_ws_after_colon, l_value,
            l_ws_after_value, l_needs_lf, l_needs_final_lf
        );

        /// HTTP 0.9 doesn't have headers.
        if (o.proto == 9) goto l_accept;
        parse_buffer1.clear();
        parse_buffer2.clear();

        /// Helper to add a header to the request.
        const auto append_header = [&]() {
            parse_buffer2.append(data + start, i - start);
            o.hdrs[parse_buffer1] = parse_buffer2;
            parse_buffer1.clear();
            parse_buffer2.clear();
        };

        /// Actual parser.
        L (l_start) {
            start = i;
            switch (data[i]) {
                case '\r': jmp(l_needs_final_lf);
                case '\n': jmp(l_accept);
                default: jmp(l_name);
            }
        }

        /// Header name.
        L (l_name) {
            switch (data[i]) {
                case '\r': jmp(l_needs_lf);
                case '\n': jmp(l_start);
                case ':':
                    parse_buffer1.append(data + start, i - start);
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
                case '\n': jmp(l_accept);
                default: ERR("Headers: needs final LF, got {}", data[i]);
            }
        }
    }

    HTTP_PARSER_END();
}

/// URI parser.
///
/// This function never throws an exception. If an exception is thrown during parsing,
/// it is stored in the result and can be rethrown by the caller.
///
/// \param input The input buffer.
/// \param consumed How many characters have been consumed from the input buffer.
/// \param uri The output uri
template <>
co_generator<http_parse_result> parser<url>(std::string_view& input, u64& consumed, url& uri) noexcept {
#undef DONE
#undef MK_URI

#define DONE (lval == acceptval or lval == path)

#define MK_URI(return_state)                                       \
    do {                                                           \
        uri.path = std::string_view{data + start, u64(i - start)}; \
        parse_buffer1.clear();                                     \
        jmp(return_state);                                         \
    } while (0)

    /// Parse uri line.
    using obj = url;
    static constexpr void* path = &&l_uri_path;
    HTTP_PARSER_INIT()
    goto l_uri_path_init;
    URI_PARSER(l_accept, MK_URI, uri)
    UNREACHABLE();
l_accept : {
    consumed += i;
    if (uri.path.empty()) MK_URI(l_next);
l_next:
    co_yield http_parse_result{http_parse_result_code::success, nullptr};
    co_return;
}
}
#undef L
#undef L_SEC
#undef L_DECLS
#undef URI_PARSER
#undef NOT_RES
#undef jmp
#undef jmp_if_req
#undef jmp_if_res
#undef ERR
#undef MK_URI
#undef PERC_FST
#undef PERC_SND
} // namespace detail

/// Parse a url.
url::url(std::string_view sv) {
    /// Parse the url.
    u64 consumed = 0;
    auto parser = detail::parser(sv, consumed, *this);
    auto [code, err] = *parser.begin();
    if (code == detail::http_parse_result_code::incomplete) throw std::runtime_error("Incomplete url");
    if (code == detail::http_parse_result_code::error) std::rethrow_exception(err);
    if (consumed != sv.size()) throw std::runtime_error("Excess data after url");
    ASSERT(code == detail::http_parse_result_code::success);
}

template <typename backend_t = tcp::client>
class client {
    using backend_type = backend_t;
    backend_type conn;
    std::vector<char> buffer;

public:
    explicit client(backend_type&& conn) : conn(std::move(conn)) {}

    /// Perform a request.
    ///
    /// \param req The request to perform.
    /// \param us_timeout How long to wait for a response (in microseconds).
    ///     A value of 0 means no timeout.
    /// \throw std::runtime_error If the request fails.
    /// \return The response.
    template <typename body_t = std::string>
    response<body_t> perform(request<body_t>&& req, chrono::microseconds us_timeout = 1s) {
        if (us_timeout < 0us) throw std::runtime_error("Timeout must be positive");

        /// Send the request.
        req.hdrs["Host"] = conn.host();
        if (not req.hdrs.has("Connection")) req.hdrs["Connection"] = "keep-alive";
        req.send(conn);

        /// Read the response.
        auto res = response<body_t>{};
        auto now = chrono::high_resolution_clock::now();

        /// Create a parser.
        std::string_view sv;
        u64 consumed = 0;
        auto parser_coro = detail::parser(sv, consumed, res);
        auto parser = parser_coro.begin();
        for (;;) {
            /// Allocate space in the buffer.
            static constexpr u64 increment = 1024;
            auto old_size = buffer.size();
            buffer.resize(old_size + increment);

            /// Receive data.
            auto recvd = conn.recv(buffer.data() + old_size, increment, us_timeout.count());
            if (recvd == 0) throw std::runtime_error("Connection closed by peer");

            /// Update the string view.
            buffer.resize(old_size + recvd);
            sv = std::string_view{buffer};

            /// Advance the parser.
            auto [result, err] = *++parser;

            /// Check for errors.
            if (result == detail::http_parse_result_code::error) {
                std::rethrow_exception(err);
                UNREACHABLE();
            }

            /// Stop if we're done.
            if (result == detail::http_parse_result_code::success) {
                buffer.erase(buffer.begin(), buffer.begin() + consumed);
                break;
            }
            ASSERT(result == detail::http_parse_result_code::incomplete);

            /// Check if the timeout has been reached.
            if (us_timeout > 0us and chrono::high_resolution_clock::now() - now > us_timeout)
                throw std::runtime_error("Timeout reached");
        }

        /// Done!
        return res;
    }

    /// Perform a GET request.
    ///
    /// \param uri The URI to GET.
    /// \param hdrs The headers to send.
    /// \return The response.
    template <typename body_t = std::string>
    response<body_t> get(url url, headers hdrs = {}) {
        return perform(request<body_t>{std::move(url), std::move(hdrs)});
    }

    /// Perform a GET request.
    ///
    /// \param path The path to GET.
    /// \param hdrs The headers to send.
    /// \return The response.
    template <typename body_t = std::string>
    response<body_t> get(std::string_view path, headers hdrs = {}) {
        return perform(request<body_t>{path, std::move(hdrs)});
    }
};

/// Perform a GET request.
template <typename body_t = std::string>
inline response<body_t> get(std::string_view url) {
    return url.starts_with("https")
               ? client(net::ssl::client()).template get<body_t>(url, {{"Connection", "close"}})
               : client(net::tcp::client()).template get<body_t>(url, {{"Connection", "close"}});
}

} // namespace net::http

#endif // NET_HTTP_HH
