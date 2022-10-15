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
    auto res = client.get("http://127.0.0.1:8080/test.html").expect(200).body;
    fmt::print("{}", res);
} catch (const std::exception& e) {
    err("{}", e.what());
}