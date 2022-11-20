#include <algorithm>
#include <net/http.hh>
#include <nlohmann/json.hpp>
#include <ranges>

namespace ranges = std::ranges;
namespace http = net::http;
using namespace std::literals;
using json = nlohmann::json;

constexpr inline std::span<const char> operator"" _sp(const char* str, size_t sz) noexcept {
    return std::span<const char>{str, sz};
}

#define check test_info{},

u64 tests_run = 0;
u64 tests_failed = 0;
std::exception_ptr error;

struct test_info {
    const char* file;
    const char* function;
    u32 line;
    explicit test_info(
        const char* file = __builtin_FILE(),
        const char* function = __builtin_FUNCTION(),
        u32 line = __builtin_LINE()
    ) : file(file), function(function), line(line) {}

    void operator,(bool condition) {
        ++tests_run;
        if (!condition) {
            ++tests_failed;
            fmt::print(stderr, "\033[33m{}:{} in function \033[32m{}\033[33m:\033[1;31m test failed\033[m", file, line, function);
            if (error) {
                try {
                    std::rethrow_exception(error);
                } catch (const std::exception& e) {
                    fmt::print(stderr, "\033[1;31m: \033[0;31m{}\033[m", e.what());
                }
            }
            fmt::print(stderr, "\n");
        }
        error = {};
    }
};

bool test_chunked_encoding_parser(std::span<const char> input, const std::span<const char> result) try {
    http::response response;
    http::detail::parser_state<http::octets> state;
    auto res = http::detail::parse_body(input, state, response, http::detail::chunked_parser_state);
    return res == http::detail::st_done_state
           and response.body.size() == result.size()
           and std::memcmp(response.body.data(), result.data(), result.size()) == 0;
} catch (const std::exception& e) {
    error = std::current_exception();
    return false;
}

bool test_uri(std::string_view input) try {
    http::url uri{input, true};
    asm volatile(""
                 :
                 : "m"(uri));
    return true;
} catch (const std::exception& e) {
    error = std::current_exception();
    return false;
}

/// Escape control chars in a string for printing.
std::string escape(std::string_view str) {
    std::string res;
    for (auto c : str) {
        if (std::iscntrl(c)) res += fmt::format("\\x{:02x}", c);
        else res += c;
    }
    return res;
}

int main() {
    /// Correct chunked encoding.
    check test_chunked_encoding_parser("0\r\n\r\n"_sp, ""_sp);
    check test_chunked_encoding_parser("1d\r\nHello, world! This is a test.\r\n0\r\n\r\n"_sp, "Hello, world! This is a test."_sp);
    check test_chunked_encoding_parser("5F\r\nauto input_copy = input;"
                                       "http::response response;"
                                       "http::detail::parser_state<http::octets> state;\r\n"
                                       "D6\r\nauto res = http::detail::parse_body(input_copy, state, response, http::detail::chunked_parser_state);"
                                       "return res == http::detail::st_done_state and std::memcmp(response.body.data(), input.data(), input.size()) == 0;\r\n"
                                       "0\r\n\r\n"_sp,

                                       "auto input_copy = input;"
                                       "http::response response;"
                                       "http::detail::parser_state<http::octets> state;"
                                       "auto res = http::detail::parse_body(input_copy, state, response, http::detail::chunked_parser_state);"
                                       "return res == http::detail::st_done_state and std::memcmp(response.body.data(), input.data(), input.size()) == 0;"
                                       ""_sp);

    /// Empty buffer.
    check not test_chunked_encoding_parser("", "");

    /// Invalid chunk size.
    check not test_chunked_encoding_parser("1g\r\nHello, world! This is a test!!!!\r\n0\r\n\r\n"_sp, "Hello, world! This is a test."_sp);

    /// Test for off-by-one errors.
    check not test_chunked_encoding_parser("1b\r\nHello, world! This is a test.\r\n0\r\n\r\n"_sp, "Hello, world! This is a test."_sp);
    check not test_chunked_encoding_parser("1c\r\nHello, world! This is a test.\r\n0\r\n\r\n"_sp, "Hello, world! This is a test."_sp);
    check not test_chunked_encoding_parser("1e\r\nHello, world! This is a test.\r\n0\r\n\r\n"_sp, "Hello, world! This is a test."_sp);
    check not test_chunked_encoding_parser("1f\r\nHello, world! This is a test.\r\n0\r\n\r\n"_sp, "Hello, world! This is a test."_sp);

    /// Incorrect encoding.
    check not test_chunked_encoding_parser("FEFE", "");

#include "uri-parser-tests.inc"

    /// https://blog.sonarsource.com/security-implications-of-url-parsing-differentials/
    check not test_uri("http://a.tld\\@b.tld");

    /// Why not.
    check test_uri("https://sourceware.org/git/?p=glibc.git;a=blob;f=stdio-common/vfscanf-internal.c;h=2ad34050f373a4ec65d1a29e9392a71ff6e86c98;hb=a9acb7b39ed21386142b963aeecc35e0b468c0de");

    /// More URL tests.
    auto file = fopen("test/urltestdata.json", "r");
    if (file) {
        defer { fclose(file); };
        auto input = json::parse(file);

        for (auto& test : input) {
            if (not test.is_object()) continue;
            auto expect_error = test.contains("failure") and test["failure"].get<bool>();
            auto url = test["input"].get<std::string>();
            auto result = test_uri(url);

            /// We don’t support whitespace in URLs, or backslashes for that matter.
            if (ranges::any_of(url, [](auto c) { return std::isspace(c) or c == '\\'; })) expect_error = true;

            ++tests_run;
            if (result != not expect_error) {
                ++tests_failed;
                fmt::print(stderr, "\033[33m[URL] \033[1;31mfailed\033[m {} \033[33m{}\033[m", expect_error ? "\033[31m:(\033[m" : "\033[32m:)\033[m", escape(url));
                if (error) {
                    try {
                        std::rethrow_exception(error);
                    } catch (const std::exception& e) {
                        fmt::print(stderr, "\033[1;31m: \033[0;31m{}\033[m", e.what());
                    }
                }
                fmt::print(stderr, "\n");
                /*fmt::print(stderr, "{}\n", test.dump(4));*/
            }
            error = {};
        }

    } else err("Failed to open urltestdata.json — Skipping tests");

    /// Print results.
    fmt::print(stderr, "\033[33mSUMMARY:\n"
                       "  Tests run:    {}\n"
                       "  Tests \033[32mpassed\033[33m: \033[32m{}\033[33m\n"
                       "  Tests \033[31mfailed\033[33m: \033[31m{}\033[33m\n",
               tests_run, tests_run - tests_failed, tests_failed);
    if (tests_failed) return 1;
}
