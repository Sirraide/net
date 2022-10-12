#include <net/tcp.hh>
#include <net/http.hh>

namespace tcp = net::tcp;
namespace http = net::http;

int main() try {
    fmt::print("{}", http::get("https://www.nguh.org").body);
} catch (const std::exception& e) {
    err("{}", e.what());
}