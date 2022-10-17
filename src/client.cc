#include <net/tcp.hh>
#include <net/http.hh>
#include <net/websock.hh>
#include <net/ssl.hh>

namespace tcp = net::tcp;
namespace http = net::http;
namespace ws = net::websock;
namespace ssl = net::ssl;

int main() try {
    http::client client{tcp::client{"localhost", 8080}};
    auto res = client.get("/test.html").expect(200);
    for (const auto &[k, v] : res.hdrs.values) {
        fmt::print("{}: {}\n", k, v);
    }
} catch (const std::exception& e) {
    err("{}", e.what());
}