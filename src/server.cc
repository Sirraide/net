#include <net/tcp.hh>

namespace tcp = net::tcp;

int main() {
    /*tcp::server server;
    server.listen(8080);

    for (;;) try {
        auto conn = server.accept();
        auto msg = conn.recv();
        fmt::print("Received: {}\n", msg);
        conn.send(msg);
        conn.close();
    } catch (const std::exception& e) {
        err("Exception caught: {}", e.what());
    }*/
}