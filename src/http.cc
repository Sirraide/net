#include <net/http.hh>

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

net::http::url::url(std::string_view sv) {
    /// Parse the url.
    detail::uri_parser parser{*this};
    if (parser(sv) != sv.size() or not parser.done()) throw std::runtime_error("Not a valid URL");
}

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

constexpr inline i8 xtonum(char c) {
    if (c >= '0' and c <= '9') return static_cast<i8>(c - '0');
    else if (c >= 'A' and c <= 'F') return static_cast<i8>(c - 'A') + 10;
    else if (c >= 'a' and c <= 'f') return static_cast<i8>(c - 'a') + 10;
    else return -1;
}

constexpr bool is_gen_delim(char c) {
    return c == ':' or c == '/' or c == '?' or c == '#' or c == '[' or c == ']' or c == '@';
}

constexpr bool is_sub_delim(char c) {
    return c == ':' or c == '/' or c == '?' or c == '#' or c == '[' or c == ']' or c == '@'
           or c == '!' or c == '$' or c == '&' or c == '\'' or c == '(' or c == ')'
           or c == '*' or c == '+' or c == ',' or c == ';' or c == '=';
}

constexpr bool is_alpha(char c) {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}

constexpr bool is_digit(char c) {
    return c >= '0' and c <= '9';
}

[[gnu::flatten]] constexpr bool is_xdigit(char c) {
    return is_digit(c) or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

[[gnu::flatten]] constexpr bool is_alnum(char c) {
    return is_alpha(c) or is_digit(c);
}

constexpr bool is_unreserved(char c) {
    return is_alnum(c) or c == '-' or c == '.' or c == '_' or c == '~';
}

[[gnu::flatten]] constexpr bool is_pchar(char c) {
    return is_unreserved(c) or is_sub_delim(c) or c == ':' or c == '@';
}

u32 net::http::detail::parse_uri(std::span<const char>& input, parser_state<url>& parser, url& uri, u32 state) {
    /// Parse the request/status line.
    auto& [parse_buffer1, parse_buffer2, fst] = parser;
    const char* data = input.data();
    u64 i = 0;
    u64 start = 0;

    enum state_t : u32 {
        st_start = uri_parser_state,
        st_uri_scheme,
        st_uri_hier_part_slash,
        st_uri_authority_start,
        st_uri_authority_percent,
        st_uri_authority_percent_2,
        st_uri_host,
        st_i6,

        /// These 4 MUST be consecutive.
        st_i4,
        st_i4_2,
        st_i4_3,
        st_i4_delim,

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

        st_uri_hier_part = 1u | uri_parser_state | accepts_more_flag,
        st_uri_hostname = 2u | uri_parser_state | accepts_more_flag,
        st_uri_port = 3u | uri_parser_state | accepts_more_flag,
        st_uri_authority = 4u | uri_parser_state | accepts_more_flag,
        st_uri_path = 5u | uri_parser_state | accepts_more_flag,
        st_uri_param_name = 6u | uri_parser_state | accepts_more_flag,
        st_uri_param_val = 7u | uri_parser_state | accepts_more_flag,
        st_uri_fragment = 8u | uri_parser_state | accepts_more_flag,
    };

    static const auto validate_ip = [](url& uri) {
        in_addr a{};
        if (inet_pton(AF_INET, uri.host.data(), &a) != 1) ERR("Invalid IPv4 address");
    };

    for (; i < input.size(); i++) {
        switch (static_cast<state_t>(state)) {
            /// URI parser.
            case st_start: {
                start = i;
                switch (data[i]) {
                    /// This is technically not a valid URI, but we allow it
                    /// because URI paths sans scheme + authority are commonly
                    /// found in HTTP request lines.
                    /// TODO: Separate function or flag or sth.
                    case '/':
                        state = st_uri_path;
                        break;
                    default:
                        if (is_alpha(data[i])) {
                            state = st_uri_scheme;
                            break;
                        }

                        ERR("Invalid URI scheme");
                }
            } break;

            case st_uri_scheme: {
                switch (data[i]) {
                    case ':':
                        std::transform(data + start, data + i, std::back_inserter(uri.scheme), [](char c) { return std::tolower(c); });
                        state = st_uri_hier_part;
                        break;
                    default:
                        if (is_alnum(data[i]) or data[i] == '+' or data[i] == '-' or data[i] == '.') break;
                        ERR("Invalid URI scheme");
                }
            } break;

            /// Handles <authority> <path-abempty>, <path-absolute>, and <path-rootless>.
            /// <path-empty> is handled by returning from the function.
            case st_uri_hier_part: {
                switch (data[i]) {
                    /// <authority> <path-abempty> | <path-absolute>
                    case '/':
                        state = st_uri_hier_part_slash;
                        break;
                    /// <path-rootless>
                    default:
                        if (not isurichar(data[i])) ERR("Invalid character in URI path: '{}'", data[i]);
                        start = i;
                        state = st_uri_path;
                        break;
                }
            } break;

            case st_uri_hier_part_slash: {
                switch (data[i]) {
                    /// <authority> <path-abempty>
                    case '/':
                        state = st_uri_authority_start;
                        break;
                    /// <path-absolute>
                    default:
                        if (not isurichar(data[i])) ERR("Invalid character in URI path: '{}'", data[i]);
                        start = i;
                        state = st_uri_path;
                        break;
                }
            } break;

            case st_uri_authority_start: {
                start = i;
                [[fallthrough]];
            }

            case st_uri_authority: {
                switch (data[i]) {
                    case '@':
                        /// If we get here, then we’ve actually been parsing the userinfo,
                        /// and not the host, so we need to move it into the right place and
                        /// parse the host.
                        std::exchange(uri.userinfo, uri.host);
                        uri.userinfo.append(data + start, i - start);
                        state = st_uri_host;
                        break;
                    case '/':
                        uri.host.append(data + start, i - start);
                        start = i;
                        state = st_uri_path;
                        break;
                    case '%':
                        uri.host.append(data + start, i - start);
                        state = st_uri_authority_percent;
                        break;
                    default:
                        if (is_unreserved(data[i]) or is_sub_delim(data[i]) or data[i] == ':') {
                            state = st_uri_authority;
                            break;
                        }
                        ERR("Invalid URI authority");
                }
            } break;

            case st_uri_authority_percent: {
                PERC_FST(st_uri_authority_percent_2);
            } break;

            case st_uri_authority_percent_2: {
                PERC_SND(st_uri_authority_start, uri.host);
            } break;

            case st_uri_host: {
                switch (data[i]) {
                    case '[':
                        state = st_i6;
                        break;
                    default:
                        start = i;
                        if (is_digit(data[i])) {
                            fst = 0;
                            state = st_i4;
                            break;
                        }
                        if (is_unreserved(data[i]) or is_sub_delim(data[i]) or data[i] == ':') break;
                        state = st_uri_hostname;
                        ERR("Invalid URI authority");
                }
            } break;

            case st_uri_hostname: {
                switch (data[i]) {
                    case ':':
                        uri.host.append(data + start, i - start);
                        state = st_uri_port;
                        break;
                    case '/':
                        uri.host.append(data + start, i - start);
                        state = st_uri_path;
                        break;
                    default:
                        if (is_unreserved(data[i]) or is_sub_delim(data[i]) or data[i] == ':') break;
                        ERR("Invalid URI hostname");
                }
            } break;

            case st_i6: {
                ERR("IPv6 addresses are not supported");
            }

            case st_i4:
            case st_i4_2: {
                if (is_digit(data[i])) {
                    state++;
                    break;
                }

                switch (data[i]) {
                    case '.':
                        state = st_i4_delim;
                        fst++;
                        break;
                    case ':':
                        if (fst == 3) validate_ip(uri);
                        uri.host.append(data + start, i - start);
                        state = st_uri_port;
                        break;
                    case '/':
                        uri.host.append(data + start, i - start);
                        state = st_uri_path;
                        break;
                    default:
                        if (not is_unreserved(data[i]) and not is_sub_delim(data[i])) ERR("Invalid URI hostname");
                        state = st_uri_hostname;
                        break;
                }
            } break;

            case st_i4_3: {
                switch (data[i]) {
                    case '.':
                        state = st_i4_delim;
                        fst++;
                        break;
                    case ':':
                        if (fst == 3) validate_ip(uri);
                        uri.host.append(data + start, i - start);
                        state = st_uri_port;
                        break;
                    case '/':
                        uri.host.append(data + start, i - start);
                        state = st_uri_path;
                        break;
                    default:
                        if (not is_unreserved(data[i]) and not is_sub_delim(data[i])) ERR("Invalid URI hostname");
                        state = st_uri_hostname;
                        break;
                }
            } break;

            case st_i4_delim: {
                /// A 4th dot indicates that this is a hostname.
                if (fst == 4) goto check_host;
                if (is_digit(data[i])) {
                    state = st_i4;
                    break;
                }

                switch (data[i]) {
                    case ':':
                        if (fst == 3) validate_ip(uri);
                        uri.host.append(data + start, i - start);
                        state = st_uri_port;
                        break;
                    case '/':
                        uri.host.append(data + start, i - start);
                        state = st_uri_path;
                        break;
                    default:
                    check_host:
                        if (not is_unreserved(data[i]) and not is_sub_delim(data[i])) ERR("Invalid URI hostname");
                        state = st_uri_hostname;
                        break;
                }
            } break;

            case st_uri_port: {
                switch (data[i]) {
                    case '/':
                        start = i;
                        state = st_uri_path;
                        break;
                    default:
                        if (not is_digit(data[i])) ERR("Invalid URI port");
                        u16 old_port = uri.port;
                        uri.port = uri.port * 10 + (data[i] - '0');
                        if (++fst > 5 or uri.port < old_port) ERR("Invalid URI port");
                        break;
                }
            } break;

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
            case st_uri_scheme: uri.scheme.append(data + start, u64(i - start)); break;
            case st_uri_hostname: uri.host.append(data + start, u64(i - start)); break;
            case st_uri_authority:
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

u32 net::http::detail::parse_headers(std::span<const char>& input, parser_state<headers>& parser, headers& hdrs, u32 state) {
    /// Parse the request/status line.
    auto& [name, value] = parser;
    const char* data = input.data();
    u64 i = 0;
    u64 start = 0;

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

    /// Return the current state.
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

u32 net::http::detail::parse_body(std::span<const char>& input, parser_state<octets>& parser, http_message& msg, u32 state) {
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
                if (parser.is_response) {
                    auto& res = static_cast<response&>(msg);
                    if (res.status == 204 or res.status == 304) return st_done_state;
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

u32 net::http::detail::parse_request(std::span<const char>& input, parser_state<request>& parser, request& req, u32 state) {
    /// Parse the request/status line.
    auto& [url_parser, hdrs_parser, body_parser] = parser;
    const char* data = input.data();
    u64 i = 0;
    u64 start = 0;

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

u32 net::http::detail::parse_response(std::span<const char>& input, parser_state<response>& parser, response& res, u32 state) {
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
                parser.body_parser.is_response = true;
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

/// Perform a HTTP request.
auto net::http::perform(url&& uri, method meth, usz max_redirects) -> response {
    do {
        /// Perform the request.
        response res;
        if (uri.scheme == "https") res = client<net::ssl::client>(uri.host, uri.port).perform(request{uri, meth, {{"Connection", "close"}}});
        else if (uri.scheme == "http") res = client<net::tcp::client>(uri.host, uri.port).perform(request{uri, meth, {{"Connection", "close"}}});
        else throw std::runtime_error("Unsupported scheme: " + uri.scheme);

        /// Check if we need to follow a redirect.
        if (res.status== 301 or res.status == 302 or res.status == 303 or res.status == 307 or res.status == 308) {
            auto loc = res.hdrs["Location"];
            if (not loc) throw std::runtime_error("Redirect response missing Location header");

            /// Parse the location.
            uri = url{*loc};
            continue;
        }

        /// If not, then we’re done.
        return res;
    } while (max_redirects--);
    throw std::runtime_error("Too many redirects");
}
