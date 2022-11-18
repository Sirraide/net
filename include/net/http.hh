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
using octets = std::vector<char>;

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

/// Return an error.
#define ERR(...) throw std::runtime_error(fmt::format(__VA_ARGS__))

/// Handle the first character in a percent encoding.
#define PERC_FST(return_state)               \
    do {                                     \
        fst = xtonum(data[i]);               \
        if (fst < 0) [[unlikely]]            \
            ERR("Invalid percent encoding"); \
        state = return_state;                \
        break;                               \
    } while (0)

/// Handle the second character in a percent encoding.
#define PERC_SND(return_state, buf)          \
    do {                                     \
        i8 snd = xtonum(data[i]);            \
        if (snd < 0) [[unlikely]]            \
            ERR("Invalid percent encoding"); \
        buf += char(fst * 16 + snd);         \
        state = return_state;                \
        break;                               \
    } while (0)

/// HTTP Message.
template <typename type>
concept http_message = requires(type m) { // clang-format off
   { m.proto } -> returns<u32>;
   { m.hdrs } -> returns<headers>;
   { m.body } -> returns<octets>;
}; // clang-format on

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
template <typename result, u32 parser_impl(std::span<const char>&, parser_state<result>&, result&, u32), u32 start_state>
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
    u64 start{};
    u8 fst{};
};

/// URI parser.
///
/// Currently, this can only parse the path, query parameters, and fragment of a URI.
///
/// TODO: Make sure this complies with RFC 3986.
u32 parse_uri(std::span<const char>& input, parser_state<url>& parser, url& uri, u32 state) {
    /// Parse the request/status line.
    auto& [parse_buffer1, parse_buffer2, start, fst] = parser;
    const char* data = input.data();
    u64 i = 0;

    enum state_t : u32 {
        st_start = uri_parser_state,
        st_uri_param_name_init,
        st_uri_path_percent,
        st_uri_path_percent_2,
        st_uri_param_name_percent,
        st_uri_param_name_percent_2,
        st_uri_param_val_init,
        st_uri_param_val_percent,
        st_uri_param_val_percent_2,
        st_uri_fragment_init,
        st_uri_fragment_percent,
        st_uri_fragment_percent_2,

        st_uri_path = 1u | uri_parser_state | accepts_more_flag,
        st_uri_param_name = 2u | uri_parser_state | accepts_more_flag,
        st_uri_param_val = 3u | uri_parser_state | accepts_more_flag,
        st_uri_fragment = 4u | uri_parser_state | accepts_more_flag,
    };

    for (; i < input.size(); i++) {
        switch (static_cast<state_t>(state)) {
            /// URI parser.
            case st_start: {
                start = i;
                [[fallthrough]];
            }

            case st_uri_path: {
                switch (data[i]) {
                    case '?':
                        uri.path = std::string_view{data + start, u64(i - start)};
                        state = st_uri_param_name_init;
                        break;
                    case '%':
                        parse_buffer1.append(data + start, u64(i - start));
                        state = st_uri_path_percent;
                        break;
                    case ' ':
                        uri.path = std::string_view{data + start, u64(i - start)};
                        goto done;
                    case '#':
                        uri.path = std::string_view{data + start, u64(i - start)};
                        state = st_uri_fragment_init;
                        break;
                    default:
                        if (not isurichar(data[i])) ERR("Invalid character in URI: '{}'", data[i]);
                        [[fallthrough]];
                    case '/':
                        state = st_uri_path;
                        break;
                }
            } break;

            /// Parse a percent-encoded character in a URI path.
            case st_uri_path_percent: {
                PERC_FST(st_uri_path_percent_2);
            } break;

            case st_uri_path_percent_2: {
                PERC_SND(st_start, parse_buffer1);
            } break;

            /// URI param name.
            case st_uri_param_name_init: {
                start = i;
                [[fallthrough]];
            }

            case st_uri_param_name: {
                switch (data[i]) {
                    case '=':
                        parse_buffer1.append(data + start, u64(i - start));
                        state = st_uri_param_val_init;
                        break;
                    case '&':
                        parse_buffer1.append(data + start, u64(i - start));
                        if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = "";
                        parse_buffer1.clear();
                        state = st_uri_param_name_init;
                        break;
                    case '%':
                        parse_buffer1.append(data + start, u64(i - start));
                        state = st_uri_param_name_percent;
                        break;
                    case ' ':
                        parse_buffer1.append(data + start, u64(i - start));
                        if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = "";
                        goto done;
                    case '#':
                        parse_buffer1.append(data + start, u64(i - start));
                        if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = "";
                        state = st_uri_fragment_init;
                        break;
                    default:
                        if (not isurichar(data[i])) ERR("Invalid character in URI param name: {}", data[i]);
                        state = st_uri_param_name;
                        break;
                }
            } break;

            /// Parse a percent-encoded character in a URI param name.
            case st_uri_param_name_percent: {
                PERC_FST(st_uri_param_name_percent_2);
            } break;

            case st_uri_param_name_percent_2: {
                PERC_SND(st_uri_param_name_init, parse_buffer1);
            } break;

            /// URI param value.
            case st_uri_param_val_init: {
                start = i;
                [[fallthrough]];
            }

            case st_uri_param_val: {
                switch (data[i]) {
                    case '&':
                        parse_buffer2.append(data + start, u64(i - start));
                        if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = parse_buffer2;
                        parse_buffer1.clear();
                        parse_buffer2.clear();
                        state = st_uri_param_name_init;
                        break;
                    case '%':
                        parse_buffer2.append(data + start, u64(i - start));
                        state = st_uri_param_val_percent;
                        break;
                    case ' ':
                        parse_buffer2.append(data + start, u64(i - start));
                        if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = parse_buffer2;
                        goto done;
                    case '#':
                        parse_buffer2.append(data + start, u64(i - start));
                        if (not uri.params.has(parse_buffer1)) uri.params[parse_buffer1] = parse_buffer2;
                        state = st_uri_fragment_init;
                        break;
                    default:
                        if (not isurichar(data[i])) ERR("Invalid character in URI param value: {}", data[i]);
                        state = st_uri_param_val;
                        break;
                }
            } break;

            /// Parse a percent-encoded character in a URI param value.
            case st_uri_param_val_percent: {
                PERC_FST(st_uri_param_val_percent_2);
            } break;

            case st_uri_param_val_percent_2: {
                PERC_SND(st_uri_param_val_init, parse_buffer2);
            } break;

            /// URI fragment.
            case st_uri_fragment_init: {
                start = i;
                parse_buffer1.clear();
                [[fallthrough]];
            }

            case st_uri_fragment: {
                switch (data[i]) {
                    case '%':
                        parse_buffer1.append(data + start, i - start);
                        state = st_uri_fragment_percent;
                        break;
                    case ' ':
                        parse_buffer1.append(data + start, i - start);
                        uri.fragment = parse_buffer1;
                        goto done; /** Not uri chars. **/
                    case '?':
                    case '/':
                        state = st_uri_fragment;
                        break;
                    default:
                        if (not isurichar(data[i])) ERR("Invalid character in URI fragment: {}", data[i]);
                        state = st_uri_fragment;
                        break;
                }
            } break;

            /// Parse a percent-encoded character in a URI fragment.
            case st_uri_fragment_percent: {
                PERC_FST(st_uri_fragment_percent_2);
            }
            case st_uri_fragment_percent_2: {
                PERC_SND(st_uri_fragment_init, parse_buffer1);
            }
        }
    }

    /// Return the current state.
    L (ret) {
        /// Append remaining data.
        switch (state) {
            case st_uri_path: uri.path.append(data + start, u64(i - start)); break;
            case st_uri_param_name: parse_buffer1.append(data + start, u64(i - start)); break;
            case st_uri_param_val: parse_buffer2.append(data + start, u64(i - start)); break;
            case st_uri_fragment: parse_buffer1.append(data + start, u64(i - start)); break;
            default: break;
        }

        /// Consume parsed data.
        input = input.subspan(i);
        return state;
    }

    /// We're done!
    L (done) {
        i++;
        state = st_done_state;
        goto ret;
    }
}

/// Headers parser state.
template <>
struct parser_state<headers> {
    std::string name;
    std::string value;
    u64 start{};
};

/// HTTP headers parser.
///
/// This parses HTTP headers and the final CRLF that terminates them.
u32 parse_headers(std::span<const char>& input, parser_state<headers>& parser, headers& hdrs, u32 state) {
    /// Parse the request/status line.
    auto& [name, value, start] = parser;
    const char* data = input.data();
    u64 i = 0;

    enum state_t : u32 {
        st_start = headers_parser_state,
        st_name,
        st_colon,
        st_ws_after_colon,
        st_value,
        st_ws_after_value,
        st_needs_lf,
        st_needs_final_lf,
    };

    /// Helper to add a header to the request.
    const auto append_header = [&]() {
        std::ranges::transform(name.begin(), name.end(), name.begin(), [](auto c) { return std::tolower(c); });
        if (not value.empty()) {
            value += std::string_view{data + start, i - start};
            hdrs[name] = value;
            value.clear();
        } else {
            hdrs[name] = std::string_view{data + start, i - start};
        }
        name.clear();
    };

    for (; i < input.size(); i++) {
        switch (static_cast<state_t>(state)) {
            /// Actual parser.
            case st_start: {
                start = i;
                switch (data[i]) {
                    case '\r': state = st_needs_final_lf; break;
                    case '\n': goto done;
                    default:
                        if (not istchar(data[i])) ERR("Invalid character in header name: {}", data[i]);
                        state = st_name;
                        break;
                }
            } break;

            /// Header name.
            case st_name: {
                switch (data[i]) {
                    case '\r': state = st_needs_lf; break;
                    case '\n': state = st_start; break;
                    case ':':
                        name.append(data + start, i - start);
                        state = st_colon;
                        break;
                    default:
                        if (not istchar(data[i])) ERR("Invalid character in header name: {}", data[i]);
                        state = st_name;
                        break;
                }
            } break;

            /// Colon and whitespace.
            case st_colon: {
                start = i;
                [[fallthrough]];
            }
            case st_ws_after_colon: {
                switch (data[i]) {
                    case ' ':
                    case '\t': state = st_ws_after_colon; break;
                    default:
                        if (istext(data[i])) {
                            start = i;
                            state = st_value;
                            break;
                        }
                        ERR("Invalid character after colon in header: {}", data[i]);
                }
            } break;

            /// Header value.
            case st_value: {
                switch (data[i]) {
                    case ' ':
                    case '\t': state = st_ws_after_value; break;
                    case '\r':
                        append_header();
                        state = st_needs_lf;
                        break;
                    case '\n':
                        append_header();
                        state = st_start;
                        break;
                    default:
                        if (not istext(data[i])) ERR("Invalid character in header value: {}", data[i]);
                        state = st_value;
                        break;
                }
            } break;

            /// Whitespace after the value.
            case st_ws_after_value: {
                switch (data[i]) {
                    case ' ':
                    case '\t': state = st_ws_after_value; break;
                    case '\r':
                        append_header();
                        state = st_needs_lf;
                        break;
                    case '\n':
                        append_header();
                        state = st_start;
                        break;
                    default:
                        if (istext(data[i])) {
                            state = st_value;
                            break;
                        }
                        ERR("Invalid character in header after value: {}", data[i]);
                }
            } break;

            /// LF after header value.
            case st_needs_lf: {
                switch (data[i]) {
                    case '\n': state = st_start; break;
                    default: ERR("Headers: needs LF, got {}", data[i]);
                }
            } break;

            /// Final CRLF after the headers.
            case st_needs_final_lf: {
                switch (data[i]) {
                    case '\n': goto done;
                    default: ERR("Headers: needs final LF, got {}", data[i]);
                }
            } break;
        }
    }

    /// Return the currrent state.
    L (ret) {
        /// Append remaining data.
        switch (state) {
            case st_name: name.append(data + start, i - start); break;
            case st_value: value.append(data + start, i - start); break;
            default: break;
        }

        /// Consume parsed data.
        input = input.subspan(i);
        return state;
    }

    /// Done!
    L (done) {
        i++;
        state = st_done_state;
        goto ret;
    }
}

/// Body parser state.
template <>
struct parser_state<octets> {
    u64 len{};
    parser_state<headers> hdrs_parser;
};

/// HTTP request/response body parser.
///
/// \param input The input buffer.
/// \param message The message whose body we're parsing.
/// \param state The current state.
u32 parse_body(std::span<const char>& input, parser_state<octets>& parser, http_message auto& msg, u32 state) {
    enum state_t : u32 {
        st_start = body_parser_state,
        st_read_body,
        st_chunk_size = chunked_parser_state,
        st_in_chunk_size,
        st_lf_after_chunk_size,
        st_read_chunk,
        st_cr_after_chunk_data,
        st_lf_after_chunk_data,
        st_lf_after_last_chunk,
        st_trailers = body_parser_state | headers_parser_state | chunked_parser_state | accepts_more_flag,
        st_read_until_conn_close = 1u | body_parser_state | accepts_more_flag,
    };

    /// Trailers parser.
    if (state & headers_parser_state) return parse_headers(input, parser.hdrs_parser, msg.hdrs, state);

    /// Actual body parser.
    u64 i = 0;
    const char* data = input.data();
    for (; i < input.size(); i++) {
        switch (static_cast<state_t>(state)) {
            case st_start: {
                /// All 1xx (informational), 204 (no content), and 304 (not modified)
                /// responses MUST NOT include a message-body.
                if (msg.proto == 9) return st_done_state;
                if constexpr (requires { {msg.status} -> returns<u32>; }) {
                    if (msg.status == 204 or msg.status == 304) return st_done_state;
                }

                /// If a Transfer-Encoding header field (section 14.41) is present and
                /// has any value other than "identity", then the transfer-length is
                /// defined by use of the "chunked" transfer-coding (section 3.6),
                /// unless the message is terminated by closing the connection.
                auto t = msg.hdrs["Transfer-Encoding"];
                if (t and *t != "identity") {
                    state = st_chunk_size;
                    goto chunked; /// Jump to chunked parser.
                }

                /// If a Content-Length header field (section 14.13) is present, its
                /// decimal value in OCTETs represents both the entity-length and the
                /// transfer-length.
                ///
                /// If a message is received with both a Transfer-Encoding header field
                /// and a Content-Length header field, the latter MUST be ignored.
                if (auto l = msg.hdrs["Content-Length"]; l and (not t or *t == "identity")) {
                    parser.len = std::stoull(*l);
                    goto read_body;
                }

                /// Otherwise, the end of the message body is indicated by the closing
                /// of the connection.
                goto read_until_conn_close;
            }

            /// Read up to a certain number of bytes from the input.
            read_body:
            case st_read_body: {
                auto chunk = std::min<u64>(parser.len, input.size());
                msg.body.reserve(msg.body.size() + chunk);
                msg.body.insert(
                    msg.body.end(),
                    input.begin(),
                    input.begin() + static_cast<std::ptrdiff_t>(chunk)
                );

                /// We've read the entire body.
                parser.len -= chunk;
                input = input.subspan(chunk);
                if (parser.len == 0) return st_done_state;

                /// Need more data.
                return st_read_body;
            }

            /// Read the entire input until the connection is closed.
            read_until_conn_close:
            case st_read_until_conn_close: {
                msg.body.reserve(msg.body.size() + input.size());
                msg.body.insert(
                    msg.body.end(),
                    input.begin(),
                    input.end()
                );

                /// Need more data.
                input = input.subspan(input.size());
                return st_read_until_conn_close;
            }

            /// Chunk size.
            chunked:
            case st_chunk_size: {
                switch (data[i]) {
                    case '0' ... '9':
                    case 'a' ... 'f':
                    case 'A' ... 'F': {
                        auto old_len = parser.len;
                        parser.len *= 16;
                        parser.len += xtonum(data[i]);
                        if (parser.len < old_len) ERR("Chunk size overflow");
                        state = st_in_chunk_size;
                    } break;

                    default: ERR("Invalid character in chunk size: {}", data[i]);
                }
            } break;

            case st_in_chunk_size: {
                switch (data[i]) {
                    case '0' ... '9':
                    case 'a' ... 'f':
                    case 'A' ... 'F': {
                        auto old_len = parser.len;
                        parser.len *= 16;
                        parser.len += xtonum(data[i]);
                        if (parser.len < old_len) ERR("Chunk size overflow");
                    } break;

                    case '\r':
                        state = parser.len == 0 ? st_lf_after_last_chunk : st_lf_after_chunk_size;
                        break;

                    default: ERR("Invalid character in chunk size: {}", data[i]);
                }
            } break;

            /// LF after chunk size.
            case st_lf_after_chunk_size: {
                switch (data[i]) {
                    case '\n': state = st_read_chunk; break;
                    default: ERR("Expected LF after chunk size, got {}", data[i]);
                }
            } break;

            /// Last chunk.
            case st_lf_after_last_chunk: {
                switch (data[i]) {
                    case '\n': state = st_trailers; break;
                    default: ERR("Expected LF after last chunk, got {}", data[i]);
                }
            } break;

            /// Read chunk.
            case st_read_chunk: {
                auto chunk = std::min<u64>(parser.len, input.size() - i);
                msg.body.reserve(msg.body.size() + chunk);
                msg.body.insert(
                    msg.body.end(),
                    input.begin() + static_cast<std::ptrdiff_t>(i),
                    input.begin() + static_cast<std::ptrdiff_t>(i + chunk)
                );

                /// We've read the entire chunk.
                parser.len -= chunk;
                if (parser.len == 0) {
                    state = st_cr_after_chunk_data;
                    i += chunk - 1;
                    break;
                }

                /// Need more data.
                input = input.subspan(i + chunk);
                return st_read_chunk;
            }

            /// CR after chunk data.
            case st_cr_after_chunk_data: {
                switch (data[i]) {
                    case '\r': state = st_lf_after_chunk_data; break;
                    default: ERR("Expected CR after chunk data, got {}", data[i]);
                }
            } break;

            /// LF after chunk data.
            case st_lf_after_chunk_data: {
                switch (data[i]) {
                    case '\n': state = st_chunk_size; break;
                    default: ERR("Expected LF after chunk data, got {}", data[i]);
                }
            } break;

            /// Trailers.
            case st_trailers: {
                input = input.subspan(i);
                return parse_headers(input, parser.hdrs_parser, msg.hdrs, headers_parser_state);
            }
        }
    }

    input = input.subspan(i);
    return state;
}

/// Request parser state.
template <>
struct parser_state<request> {
    u64 start{};
    parser_state<url> url_parser;
    parser_state<headers> hdrs_parser;
    parser_state<octets> body_parser;
};

/// HTTP request parser.
///
/// \param input The input buffer.
/// \param req The output request.
/// \param state The current state of the parser.
u32 parse_request(std::span<const char>& input, parser_state<request>& parser, request& req, u32 state) {
    /// Parse the request/status line.
    auto& [start, url_parser, hdrs_parser, body_parser] = parser;
    const char* data = input.data();
    u64 i = 0;

    enum state_t : u32 {
        st_start = request_parser_state,
        st_method,
        st_ws_after_method,
        st_ws_after_uri,
        st_H,
        st_HT,
        st_HTT,
        st_HTTP,
        st_http_ver_maj,
        st_http_ver_rest,
        st_http_ver_min,
        st_ws_after_ver,
        st_needs_lf,
        st_body = body_parser_state,
    };

    /// Nested parsers.
    if (state & uri_parser_state) [[unlikely]]
        goto uri_parser;
    if (state & headers_parser_state) [[unlikely]]
        goto headers_parser;
    if (state & body_parser_state) [[unlikely]]
        return parse_body(input, body_parser, req, state);

    /// Parser entry point.
    for (; i < input.size(); i++) {
        switch (static_cast<state_t>(state)) {
            case st_ws_after_uri: {
                switch (data[i]) {
                    case ' ': state = st_ws_after_uri; break;
                    case '\r':
                        req.proto = 9;
                        state = st_needs_lf;
                        break;
                    case '\n':
                        /// HTTP/0.9 doesn't have headers.
                        req.proto = 9;
                        state = st_body;
                        break;
                    case 'H': state = st_H; break;
                    default: ERR("Invalid character after URI in request: {}", data[i]);
                }
            } break;

            /// Parser entry point.
            case st_start: {
                start = i;

                /// Requests may be preceded by CRLF for some reason...
                if (data[i] == '\r' or data[i] == '\n') {
                    state = st_start;
                    break;
                }

                state = st_method;
                break;
            }

            /// Parse the method.
            case st_method: {
                /// Whitespace after the method.
                if (data[i] == ' ') {
                    switch (i - start) {
                        case 3:
                            if (std::memcmp(data + start, "GET ", 4) == 0) [[likely]] {
                                req.meth = method::get;
                                state = st_ws_after_method;
                                break;
                            }
                            ERR("Method not supported");
                        case 4:
                            if (std::memcmp(data + start, "HEAD", 4) == 0) {
                                req.meth = method::head;
                                state = st_ws_after_method;
                                break;
                            } else if (std::memcmp(data + start, "POST", 4) == 0) {
                                req.meth = method::post;
                                state = st_ws_after_method;
                                break;
                            }
                            ERR("Method not supported");
                        default:
                            ERR("Method not supported");
                    }
                }
                if (data[i] < 'A' or data[i] > 'Z') ERR("Invalid character in method name: '{}'", data[i]);
            } break;

            case st_ws_after_method: {
                switch (data[i]) {
                    case ' ': state = st_ws_after_method; break;
                    case '/': goto uri_parser_init;
                    default: ERR("Invalid character after method name: '{}'", data[i]);
                }
            } break;

            uri_parser_init : {
                input = input.subspan(i);
                state = uri_parser_state;
            }

            uri_parser : {
                state = parse_uri(input, url_parser, req.uri, state);

                /// URI parser is done.
                if (state == st_done_state) {
                    if (input.empty()) return st_ws_after_uri;

                    /// Update our state.
                    state = st_ws_after_uri;
                    data = input.data();
                    i = 0;
                    break;
                }

                /// URI parser needs more data.
                return state;
            }

            case st_H: {
                if (data[i] == 'T') {
                    state = st_HT;
                    break;
                }
                ERR("Expected T after H, got {}", data[i]);
            }

            case st_HT: {
                if (data[i] == 'T') {
                    state = st_HTT;
                    break;
                }
                ERR("Expected T after HT, got {}", data[i]);
            }

            case st_HTT: {
                if (data[i] == 'P') {
                    state = st_HTTP;
                    break;
                }
                ERR("Expected P after HTT, got {}", data[i]);
            }

            case st_HTTP: {
                if (data[i] == '/') {
                    state = st_http_ver_maj;
                    break;
                }
                ERR("Expected / after HTTP, got {}", data[i]);
            }

            case st_http_ver_maj: {
                switch (data[i]) {
                    case '0': state = st_http_ver_maj; break;
                    case '1': state = st_http_ver_rest; break;
                    case '2' ... '9': ERR("Unsupported http major version: {}", data[i] - '0');
                    default: ERR("Expected major version after HTTP/, got {}", data[i]);
                }
            } break;

            case st_http_ver_rest: {
                if (data[i] == '.') {
                    state = st_http_ver_min;
                    break;
                }
                ERR("Expected . in protocol version, got {}", data[i]);
            }

            case st_http_ver_min: {
                switch (data[i]) {
                    case '0':
                        req.proto = 10;
                        state = st_ws_after_ver;
                        break;
                    case '1':
                        req.proto = 11;
                        state = st_ws_after_ver;
                        break;
                    case '\r': state = st_needs_lf; break;
                    case '\n': i++; goto headers_parser_init;
                    case ' ': state = st_ws_after_ver; break;
                    case '2' ... '9': ERR("Unsupported http minor version: {}", data[i] - '0');
                    default: ERR("Invalid character in protocol version: {}", data[i]);
                }
            } break;

            case st_ws_after_ver: {
                switch (data[i]) {
                    case ' ': state = st_ws_after_ver; break;
                    case '\n': i++; goto headers_parser_init;
                    case '\r': state = st_needs_lf; break;
                    default: ERR("Invalid character in whitespace after protocol version: {}", data[i]);
                }
            } break;

            case st_needs_lf: {
                if (data[i] == '\n') {
                    i++;
                    goto headers_parser_init;
                }
                ERR("Expected LF, got {}", data[i]);
            }

            headers_parser_init : {
                input = input.subspan(i);
                state = headers_parser_state;
            }

            headers_parser : {
                state = parse_headers(input, hdrs_parser, req.hdrs, state);

                /// Headers parser is done.
                if (state == st_done_state) {
                    if (input.empty()) return st_body;

                    /// Update our state.
                    state = st_body;
                    data = input.data();
                    i = 0;
                    break;
                }

                /// Headers parser needs more data.
                return state;
            }

            case st_body: {
                /// We don't want to deal w/ parsing HTTP/0.9 bodies.
                if (req.proto == 9) break;

                /// Parse the body.
                return parse_body(input, body_parser, req, state);
            }
        }
    }

    input = input.subspan(i);
    return state;
}

/// Request parser state.
template <>
struct parser_state<response> {
    parser_state<headers> hdrs_parser;
    parser_state<octets> body_parser;
};

/// HTTP response parser.
///
/// \param input The input buffer.
/// \param consumed How many characters have been consumed from the input buffer.
/// \param res The output response.
u32 parse_response(std::span<const char>& input, parser_state<response>& parser, response& res, u32 state) {
    /// Parse the request/status line.
    auto& [hdrs_parser, body_parser] = parser;
    const char* data = input.data();
    u64 i = 0;

    enum state_t : u32 {
        st_start = response_parser_state,
        st_needs_lf,
        st_H,
        st_HT,
        st_HTT,
        st_HTTP,
        st_http_ver_maj,
        st_http_ver_rest,
        st_http_ver_min,
        st_ws_after_ver,
        st_status_2nd,
        st_status_3rd,
        st_first_ws_after_status,
        st_ws_after_status,
        st_reason_phrase,
        st_body = body_parser_state,
    };

    /// Nested parsers.
    if (state & headers_parser_state) [[unlikely]]
        goto headers_parser;
    if (state & body_parser_state) [[unlikely]]
        return parse_body(input, body_parser, res, state);

    for (; i < input.size(); i++) {
        switch (static_cast<state_t>(state)) {
            /// Parser entry point.
            case st_start: {
                if (data[i] == 'H') {
                    state = st_H;
                    break;
                }
                ERR("Expected HTTP version in status line");
            }

            case st_H: {
                if (data[i] == 'T') {
                    state = st_HT;
                    break;
                }
                ERR("Expected T after H, got {}", data[i]);
            }

            case st_HT: {
                if (data[i] == 'T') {
                    state = st_HTT;
                    break;
                }
                ERR("Expected T after HT, got {}", data[i]);
            }

            case st_HTT: {
                if (data[i] == 'P') {
                    state = st_HTTP;
                    break;
                }
                ERR("Expected P after HTT, got {}", data[i]);
            }

            case st_HTTP: {
                if (data[i] == '/') {
                    state = st_http_ver_maj;
                    break;
                }
                ERR("Expected / after HTTP, got {}", data[i]);
            }

            case st_http_ver_maj: {
                switch (data[i]) {
                    case '0': state = st_http_ver_maj; break;
                    case '1': state = st_http_ver_rest; break;
                    case '2' ... '9': ERR("Unsupported http major version: {}", data[i] - '0');
                    default: ERR("Expected major version after HTTP/, got {}", data[i]);
                }
            } break;

            case st_http_ver_rest: {
                if (data[i] == '.') {
                    state = st_http_ver_min;
                    break;
                }
                ERR("Expected . in protocol version, got {}", data[i]);
            }

            case st_http_ver_min: {
                switch (data[i]) {
                    case '0':
                        res.proto = 10;
                        state = st_ws_after_ver;
                        break;
                    case '1':
                        res.proto = 11;
                        state = st_ws_after_ver;
                        break;
                    case '\r': state = st_needs_lf; break;
                    case '\n': i++; goto headers_parser_init;
                    case ' ': state = st_ws_after_ver; break;
                    case '2' ... '9': ERR("Unsupported http minor version: {}", data[i] - '0');
                    default: ERR("Invalid character in protocol version: {}", data[i]);
                }
            } break;

            headers_parser_init : {
                input = input.subspan(i);
                state = headers_parser_state;
            }

            headers_parser : {
                state = parse_headers(input, hdrs_parser, res.hdrs, state);

                /// Headers parser is done.
                if (state == st_done_state) {
                    if (input.empty()) return st_body;

                    /// Update our state.
                    state = st_body;
                    data = input.data();
                    i = 0;
                    break;
                }

                /// Headers parser needs more data.
                return state;
            }

            case st_ws_after_ver: {
                switch (data[i]) {
                    case ' ': state = st_ws_after_ver; break;
                    default:
                        if (std::isdigit(data[i])) {
                            res.status = (data[i] - '0') * 100;
                            state = st_status_2nd;
                            break;
                        }
                        ERR("Invalid character in whitespace after protocol version: {}", data[i]);
                }
            } break;

            case st_status_2nd: {
                if (std::isdigit(data[i])) {
                    res.status += (data[i] - '0') * 10;
                    state = st_status_3rd;
                    break;
                }
                ERR("Status code may only contain digits");
            }

            case st_status_3rd: {
                if (std::isdigit(data[i])) {
                    res.status += (data[i] - '0');
                    state = st_first_ws_after_status;
                    break;
                }
                ERR("Status code may only contain digits");
            }

            case st_first_ws_after_status: {
                switch (data[i]) {
                    case ' ': state = st_ws_after_status; break;
                    case '\r': state = st_needs_lf; break;
                    case '\n': i++; goto headers_parser_init;
                    default: ERR("Invalid character after status code: {}", data[i]);
                }
            } break;

            case st_ws_after_status: {
                switch (data[i]) {
                    case ' ': state = st_ws_after_status; break;
                    case '\r': state = st_needs_lf; break;
                    case '\n': i++; goto headers_parser_init;
                    default: goto reason_phrase; /// (!)
                }
            } break;

            case st_reason_phrase: {
            reason_phrase:
                if (not istext(data[i])) {
                    if (data[i] == '\r') {
                        state = st_needs_lf;
                        break;
                    }

                    else if (data[i] == '\n') {
                        i++;
                        goto headers_parser_init;
                    }

                    ERR("Reason phrase contains invalid character: '{}'", data[i]);
                }
                state = st_reason_phrase;
                break;
            }

            case st_needs_lf: {
                if (data[i] == '\n') {
                    i++;
                    goto headers_parser_init;
                }
                ERR("Expected LF, got {}", data[i]);
            }

            /// Parse the response body.
            case st_body: {
                /// We don't want to deal w/ parsing HTTP/0.9 bodies.
                if (res.proto == 9) break;

                /// Parse the body.
                return parse_body(input, body_parser, res, state);
            }
        }
    }

    /// Return the current state.
    input = input.subspan(i);
    return state;
}

using uri_parser = parser<url, parse_uri, uri_parser_state>;
using headers_parser = parser<headers, parse_headers, headers_parser_state>;
using request_parser = parser<request, parse_request, request_parser_state>;
using response_parser = parser<response, parse_response, response_parser_state>;

template <typename res>
using body_parser = parser<response, parse_body<res>, body_parser_state>;

#undef ERR
#undef PERC_FST
#undef PERC_SND
} // namespace detail

/// Parse a url.
url::url(std::string_view sv) {
    /// Parse the url.
    detail::uri_parser parser{*this};
    if (parser(sv) != sv.size() or not parser.done()) throw std::runtime_error("Not a valid URL");
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
        [[maybe_unused]] auto now = chrono::high_resolution_clock::now();

        /// Create a parser.
        auto parser = detail::response_parser{res};
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
