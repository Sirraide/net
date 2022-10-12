#include <net/tcp.hh>

namespace tcp = net::tcp;

int main() try {
    tcp::client client;
    client.connect("localhost", 8080);
    client.send("Hello, world!");
    fmt::print("Received: {}\n", client.recv());
    client.close();
} catch (const std::exception& e) {
    err("Exception caught: {}", e.what());
}