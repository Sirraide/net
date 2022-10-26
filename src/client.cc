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
    https::client client{"www.nguh.org", 443};
    auto res = client.get("/speedrun").expect(200);
    fmt::print("RESPONSE:\n");
    for (const auto &[k, v] : res.hdrs.values) {
        fmt::print("{}: {}\n", k, v);
    }
    fmt::print("\nBODY:\n{}\n", std::string_view{res.body});
}

void websocket() {
    ws::client client;
    client.on_close = [](ws::message&& m) {
        if (auto code = m.buffer.try_extract<u16>(); code)
            fmt::print("Websocket closed: {} {}\n", ntohs(*code), m.buffer.str());
        else fmt::print("Websocket closed\n");
    };
    client.on_text = client.on_binary = [](ws::message&& m) {
        fmt::print("Received: {}\n", m.buffer.str());
    };
    client.on_ready = [&] { client.send_frame(ws::opcode::text, "Hello, world!"); };
    client.connect(true, "echo.websocket.events", "/");
}

int main() {
    httpclient();
}