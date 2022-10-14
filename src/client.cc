#include <net/tcp.hh>
#include <net/http.hh>
#include <net/websock.hh>
#include <net/ssl.hh>

namespace tcp = net::tcp;
namespace http = net::http;
namespace ws = net::websock;
namespace ssl = net::ssl;

int main() try {
    ssl::client ssl;
    ssl.connect("www.nguh.org", 443);
    ssl.recv_async<std::string>(1, [](const std::string& data){
        fmt::print("{}", data);
        return data.size();
    }, [](const std::exception& e){
        std::rethrow_exception(std::current_exception());
    });
    ssl.send(std::string_view{"GET / HTTP/1.1\r\nHost: www.nguh.org\r\n\r\n"});
    std::this_thread::sleep_for(std::chrono::seconds(100));
} catch (const std::exception& e) {
    err("{}", e.what());
}