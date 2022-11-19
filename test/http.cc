#include <net/http.hh>

namespace http = net::http;
using namespace std::literals;

constexpr inline std::span<const char> operator"" _sp(const char* str, size_t sz) noexcept {
    return std::span<const char>{str, sz};
}

#define check test_info{} %

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

    void operator%(bool condition) {
        ++tests_run;
        if (!condition) {
            ++tests_failed;
            fmt::print(stderr, "{}:{} in function \033[32m{}\033[m:\033[1;31m test failed\033[m", file, line, function);
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
    asm volatile("" : : "m"(uri));
    return true;
} catch (const std::exception& e) {
    error = std::current_exception();
    return false;
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

    /// These tests are taken from https://github.com/uriparser/uriparser/blob/master/test/FourSuite.cpp
    check test_uri("file:///foo/bar");
    check test_uri("mailto:user@host?subject=blah");
    check test_uri("dav:"); // empty opaque part / rel-path allowed by RFC 2396bis
    check test_uri("about:"); // empty opaque part / rel-path allowed by RFC 2396bis

    // the following test cases are from a Perl script by David A. Wheeler
    // at http://www.dwheeler.com/secure-programs/url.pl
    check test_uri("http://www.yahoo.com");
    check test_uri("http://www.yahoo.com/");
    check test_uri("http://1.2.3.4/");
    check test_uri("http://www.yahoo.com/stuff");
    check test_uri("http://www.yahoo.com/stuff/");
    check test_uri("http://www.yahoo.com/hello%20world/");
    check test_uri("http://www.yahoo.com?name=obi");
    check test_uri("http://www.yahoo.com?name=obi+wan&status=jedi");
    check test_uri("http://www.yahoo.com?onery");
    check test_uri("http://www.yahoo.com#bottom");
    check test_uri("http://www.yahoo.com/yelp.html#bottom");
    check test_uri("https://www.yahoo.com/");
    check test_uri("ftp://www.yahoo.com/");
    check test_uri("ftp://www.yahoo.com/hello");
    check test_uri("demo.txt");
    check test_uri("demo/hello.txt");
    check test_uri("demo/hello.txt?query=hello#fragment");
    check test_uri("/cgi-bin/query?query=hello#fragment");
    check test_uri("/demo.txt");
    check test_uri("/hello/demo.txt");
    check test_uri("hello/demo.txt");
    check test_uri("/");
    check test_uri("");
    check test_uri("#");
    check test_uri("#here");

    // Wheeler's script says these are invalid, but they aren't
    check test_uri("http://www.yahoo.com?name=%00%01");
    check test_uri("http://www.yaho%6f.com");
    check test_uri("http://www.yahoo.com/hello%00world/");
    check test_uri("http://www.yahoo.com/hello+world/");
    check test_uri("http://www.yahoo.com?name=obi&");
    check test_uri("http://www.yahoo.com?name=obi&type=");
    check test_uri("http://www.yahoo.com/yelp.html#");
    check test_uri("//");

    // the following test cases are from a Haskell program by Graham Klyne
    // at http://www.ninebynine.org/Software/HaskellUtils/Network/URITest.hs
    check test_uri("http://example.org/aaa/bbb#ccc");
    check test_uri("mailto:local@domain.org");
    check test_uri("mailto:local@domain.org#frag");
    check test_uri("HTTP://EXAMPLE.ORG/AAA/BBB#CCC");
    check test_uri("//example.org/aaa/bbb#ccc");
    check test_uri("/aaa/bbb#ccc");
    check test_uri("bbb#ccc");
    check test_uri("#ccc");
    check test_uri("#");
    check test_uri("A'C");

    // escapes
    check test_uri("http://example.org/aaa%2fbbb#ccc");
    check test_uri("http://example.org/aaa%2Fbbb#ccc");
    check test_uri("%2F");
    check test_uri("aaa%2Fbbb");

    // ports
    check test_uri("http://example.org:80/aaa/bbb#ccc");
    check test_uri("http://example.org:/aaa/bbb#ccc");
    check test_uri("http://example.org./aaa/bbb#ccc");
    check test_uri("http://example.123./aaa/bbb#ccc");

    // bare authority
    check test_uri("http://example.org");

    // IPv6 literals (from RFC2732):
    /*check test_uri("http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html");
    check test_uri("http://[1080:0:0:0:8:800:200C:417A]/index.html");
    check test_uri("http://[3ffe:2a00:100:7031::1]");
    check test_uri("http://[1080::8:800:200C:417A]/foo");
    check test_uri("http://[::192.9.5.5]/ipng");
    check test_uri("http://[::FFFF:129.144.52.38]:80/index.html");
    check test_uri("http://[2010:836B:4179::836B:4179]");
    check test_uri("//[2010:836B:4179::836B:4179]");*/

    // Random other things that crop up
    check test_uri("http://example/Andr&#567;");
    check test_uri("file:///C:/DEV/Haskell/lib/HXmlToolbox-3.01/examples/");

    /// Print results.
    fmt::print("Tests run: {}, tests failed: {}\n", tests_run, tests_failed);
    if (tests_failed) return 1;
}
