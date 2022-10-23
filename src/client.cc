#include <net/http.hh>
#include <net/ssl.hh>
#include <net/tcp.hh>
#include <net/websock.hh>
#include <ranges>

namespace tcp = net::tcp;
namespace http = net::http;
namespace https = net::https;
namespace ws = net::websock;
namespace ssl = net::ssl;

using net::http::octets;

void httpclient() {
    http::client client{"localhost", 8080};
    auto res = client.get("/test.html").expect(200);
    fmt::print("Response headers:\n");
    for (const auto &[k, v] : res.hdrs.values) {
        fmt::print("    {}: {}\n", k, v);
    }
}

void websocket() {
    ws::client<net::tcp::client> client;
    client.on_close = [](ws::message&& m) {
        if (auto code = m.buffer.try_extract<u16>(); code) fmt::print("Websocket closed: {} {}\n", ntohs(*code), m.buffer.str());
        else fmt::print("Websocket closed\n");
    };
    client.on_text = client.on_binary = [](ws::message&& m) {
        fmt::print("Received: {}\n", m.buffer.str());
    };
    client.connect(false, "localhost", "/", 8080);
}

int main() {
    websocket();
}