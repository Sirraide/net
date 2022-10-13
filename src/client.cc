#include <net/tcp.hh>
#include <net/http.hh>
#include <net/websock.hh>

namespace tcp = net::tcp;
namespace http = net::http;
namespace ws = net::websock;

int main() try {
    ws::client client{"wss://echo.websocket.events"};
} catch (const std::exception& e) {
    err("{}", e.what());
}