#ifndef NET_HTTP_HH
#define NET_HTTP_HH

#include "ssl.hh"
#include "utils.hh"

#include <atomic>
#include <mutex>
#include <unordered_map>

namespace net::http {

/// HTTP Verbs.
enum struct method {
    get
};

/// HTTP headers.
struct headers {
    std::unordered_map<std::string, std::string> values;

    /// Reference to a header value.
    struct header_ref {
        headers& parent;
        std::string key;

        /// Create a reference to a header value.
        header_ref(headers& parent, std::string&& key) : parent(parent), key(std::move(key)) {}

        /// Set the header value. This will append the value to the existing value,
        /// separated by a comma if the header already exists.
        header_ref& operator=(std::string_view value) {
            if (parent.values.contains(key)) parent.values[key] += fmt::format(", {}", value);
            else parent.values[key] = value;
            return *this;
        }

        /// Check if the header exists.
        operator bool() const { return parent.values.contains(key); }

        /// Get the header value.
        std::string_view operator*() const { return parent.values.at(key); }
    };

    /// Get a reference to a header value.
    header_ref operator[](std::string_view key) { return {*this, std::string{key}}; }

    /// Check if a certain header exists.
    bool has(const std::string& key) const { return values.contains(key); }
};

/// HTTP response.
template <typename body_t>
struct response {
    using body_type = body_t;

    u32 status{};
    body_type body;
    headers hdrs;

    response& expect(u32 code) {
        if (status != code) throw std::runtime_error(fmt::format("Expected status {}, but was {}", status, code));
        return *this;
    }
};

struct url {
    std::string data;

    url(std::convertible_to<std::string_view> auto&& data) : data(encode_uri(std::forward<decltype(data)>(data))) {}
};

/// HTTP request.
template <typename body_t = std::string>
struct request {
    using body_type = body_t;

    url path;
    headers hdrs;
    body_type body;

    /// Create a request.
    explicit request(struct url path, headers hdrs = {})
        : path(std::move(path)),
          hdrs(std::move(hdrs)) {}
};

namespace detail {

} // namespace detail

template <typename backend_t = tcp::client>
class client {
    using backend_type = backend_t;
    backend_type conn;

public:
    explicit client(backend_type&& conn) : conn(std::move(conn)) {}

    /// Perform a request.
    ///
    /// \param req The request to perform.
    /// \throw std::runtime_error If the request fails.
    /// \return The response.
    template <typename body_t = std::string>
    response<body_t> perform(const request<body_t>& req) {
        UNREACHABLE();
    }

    /// Perform a GET request.
    ///
    /// \param uri The URI to GET.
    /// \param hdrs The headers to send.
    /// \return The response.
    template <typename body_t = std::string>
    response<body_t> get(url url, headers hdrs = {}) {
        UNREACHABLE();
    }
};

/// Perform a GET request.
template <typename body_t = std::string>
inline response<body_t> get(std::string_view url) {
    return url.starts_with("https")
        ? client(net::ssl::client()).template get<body_t>(url)
        : client(net::tcp::client()).template get<body_t>(url);
}

} // namespace net::http

#endif // NET_HTTP_HH
