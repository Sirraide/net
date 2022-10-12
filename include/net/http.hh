#ifndef NET_HTTP_HH
#define NET_HTTP_HH

#include "utils.hh"

#include <atomic>
#include <curl/curl.h>
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

    long status;
    body_type body;
    headers hdrs;
};

/// HTTP request.
struct request {
    std::string uri;
    headers hdrs;
    std::vector<char> body;

    /// Create a request.
    explicit request(std::string_view uri, bool encode_url = true)
        : uri(encode_url ? encode_uri(uri) : std::string(uri)) {}
};

namespace detail {
inline std::atomic_flag curl_initialised = ATOMIC_FLAG_INIT;
inline bool curl_initialisation_done = false;

/// cURL handle.
class curl {
    CURL* handle = nullptr;
    std::mutex mtx;

public:
    /// Initialise cURL.
    curl() {
        /// Initialise cURL once.
        if (not curl_initialised.test_and_set()) {
            curl_global_init(CURL_GLOBAL_ALL);
            curl_initialisation_done = true;
        }

        /// Spin until cURL is initialised. Spinlocks should usually be avoided,
        /// but in this case it's fine because we're only spinning for a very
        /// short time.
        while (not curl_initialisation_done) continue;

        /// Create a new cURL handle.
        handle = curl_easy_init();

        /// Follow redirects.
        curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(handle, CURLOPT_MAXREDIRS, 10L);

        /// Make sure this is thread-safe.
        curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
    }

    /// Destroy the cURL handle.
    ~curl() {
        if (handle) curl_easy_cleanup(handle);
    }

    /// Perform a request.
    template <method m, typename body_type>
    response<body_type> perform(request&& req) {
        std::unique_lock lock{mtx};

        /// Set the URL.
        curl_easy_setopt(handle, CURLOPT_URL, req.uri.data());

        /// Set the HTTP method.
        if constexpr (m == method::get) curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);

        /// Set the request headers.
        struct curl_slist* headers = nullptr;
        for (auto& [key, value] : req.hdrs.values) {
            headers = curl_slist_append(headers, fmt::format("{}: {}", key, value).c_str());
        }
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);

        /// The response.
        response<body_type> res;

        /// Set the callback to write the response body.
        curl_write_callback write_cb = [](char* ptr, size_t size, size_t nmemb, void* userdata) {
            auto& body = *static_cast<body_type*>(userdata);
            body.insert(body.end(), ptr, ptr + size * nmemb);
            return size * nmemb;
        };
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(handle, CURLOPT_WRITEDATA, &res.body);

        /// Set the callback to write the response headers.
        curl_write_callback header_cb = [](char* ptr, size_t size, size_t nmemb, void* userdata) {
            auto& headers = *static_cast<struct headers*>(userdata);
            std::string_view header{ptr, size * nmemb};
            auto colon = header.find(':');
            if (colon != std::string_view::npos) {
                headers.values[std::string{header.substr(0, colon)}] = std::string{header.substr(colon + 2)};
            }
            return size * nmemb;
        };
        curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, header_cb);
        curl_easy_setopt(handle, CURLOPT_HEADERDATA, &res.hdrs);

        /// Perform the request.
        auto code = curl_easy_perform(handle);
        if (code != CURLE_OK) throw std::runtime_error(curl_easy_strerror(code));

        /// Get the response status.
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &res.status);

        /// Free the headers.
        curl_slist_free_all(headers);

        /// Return the response.
        return res;
    }
};
} // namespace detail

/// Perform a GET request.
template <typename body = std::string>
inline response<body> get(std::string_view url) {
    return detail::curl().perform<method::get, body>(request{url});
}

} // namespace net::http

#endif // NET_HTTP_HH
