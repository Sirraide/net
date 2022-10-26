#ifndef NET_UTILS_HH
#define NET_UTILS_HH

#include <algorithm>
#include <chrono>
#include <coroutine>
#include <cstdint>
#include <cstdio>
#include <cxxabi.h>
#include <exception>
#include <execinfo.h>
#include <fcntl.h>
#include <fmt/format.h>
#include <iterator>
#include <random>
#include <sys/mman.h>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <vector>
#include <span>

#define CAT_(X, Y) X##Y
#define CAT(X, Y)  CAT_(X, Y)

#define STR_(X) #X
#define STR(X)  STR_(X)

#define CAR(X, ...) X
#define CDR(X, ...) __VA_ARGS__

#define nocopy(type)            \
    type(const type&) = delete; \
    type& operator=(const type&) = delete

#define nomove(type)       \
    type(type&&) = delete; \
    type& operator=(type&&) = delete

#define ASSERT(condition, ...)                                                                               \
    do {                                                                                                     \
        if (!(condition))                                                                                    \
            assertion_error(#condition, FILENAME, __LINE__, __PRETTY_FUNCTION__ __VA_OPT__(, ) __VA_ARGS__); \
    } while (0)

#define FILENAME (this_file_name())

#define UNREACHABLE() ASSERT(false, "UNREACHABLE")

#ifndef RAISE_COMPILE_ERROR
#    define RAISE_COMPILE_ERROR(msg) ([]<bool _b = false> { static_assert(_b, msg); }())
#endif

#ifndef NDEBUG
#    define VERBOSE(...)           info(__VA_ARGS__)
#    define DEBUG_LOCATION_DECL    const char *filename = __builtin_FILE(), int line = __builtin_LINE()
#    define DEBUG_LOCATION_DEF     const char *filename, int line
#    define DEBUG_LOCATION_AS_ARGS filename, line
#else
#    define VERBOSE(...) void()
#    define DEBUG_LOCATION_DECL
#    define DEBUG_LOCATION_DEF
#    define DEBUG_LOCATION_AS_ARGS
#endif

#define DEBUG_LOCATION() ({                                                                          \
    VERBOSE("\033[1;33m{} called in {}:{}", __PRETTY_FUNCTION__, extract_file_name(filename), line); \
    VERBOSE("Stack trace:\n{}", current_stacktrace());                                               \
})

/// Check if (enumeration::$$min <= x && x <= enumeration::$$max)
#define ENUMERATOR(x, enumeration) __extension__({                                                          \
    using temp_value_type = std::remove_cvref_t<decltype(x)>;                                               \
    temp_value_type temp_value = x;                                                                         \
    temp_value >= temp_value_type(enumeration::$$min) && temp_value <= temp_value_type(enumeration::$$max); \
})

#define defer auto CAT($$defer_struct_instance_, __COUNTER__) = defer_type_operator_lhs_instance % [&]

/// Equivalent to std::is_same_v<std::remove_cvref_t<T>, std::remove_cvref_t<U>>.
template <typename T, typename U>
constexpr inline bool is = std::is_same_v<std::remove_cvref_t<T>, std::remove_cvref_t<U>>;

template <typename T, typename U>
concept returns = is<T, U>;

/// Get the first element of a parameter pack.
template <typename T, typename... Ts>
constexpr inline T& car(T&& t, Ts&&...) { return std::forward<T>(t); }

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef float f32;
typedef double f64;

inline FILE* log_stream;

/// Start time.
inline std::chrono::time_point start_time = std::chrono::system_clock::now();

[[gnu::constructor]] static void init() {
    log_stream = stdout;
    fflush(log_stream);
    setbuf(log_stream, nullptr);
}

/// Get the current time as hh:mm:ss.mmm.
inline std::string current_time() {
    /// Format the current time as hh:mm:ss.mmm using clock_gettime().
    timespec ts{};
    tm tm{};
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    return fmt::format("{:02}:{:02}:{:02}.{:03}", tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

template <typename... args_t>
inline void info(fmt::format_string<args_t...> fmt_str, args_t&&... args) {
    fmt::print(log_stream, "\033[33m[{}] Info: ", current_time());
    fmt::print(log_stream, fmt_str, std::forward<args_t>(args)...);
    fmt::print(log_stream, "\033[m\n");
}

template <typename callable_t>
struct defer_type {
    using callable_type = callable_t;
    const callable_type function;
    explicit defer_type(callable_t _function) : function(_function) {}
    inline ~defer_type() { function(); }
    nocopy(defer_type);
    nomove(defer_type);
};

struct defer_type_operator_lhs {
    template <typename callable_t>
    auto operator%(callable_t rhs) -> defer_type<callable_t> { return defer_type<callable_t>(rhs); }
};
inline defer_type_operator_lhs defer_type_operator_lhs_instance;

constexpr const char* extract_file_name(const char* fname) {
    const char *ptr = __builtin_strchr(fname, '/'), *last = ptr;
    if (!last) return fname;
    while (last) {
        ptr = last;
        last = __builtin_strchr(last + 1, '/');
    }
    return ptr + 1;
}

consteval const char* this_file_name(const char* fname = __builtin_FILE()) {
    return extract_file_name(fname);
}

std::vector<char> map_file(std::string_view filename);

/// Get the current stacktrace.
inline std::string current_stacktrace() {
    void* buffer[15];
    auto nptrs = backtrace(buffer, 15);

    char** strings = backtrace_symbols(buffer, nptrs);
    if (strings == nullptr) return "";

    /// The standard mandates that the buffer used for __cxa_demangle()
    /// be allocated with malloc() since it may expand it using realloc().
    char* demangled_name = (char*) malloc(1024);
    defer { free(demangled_name); };

    /// Get the entries.
    std::string s;
    for (int i = 2; i < nptrs; i++) {
        /// The mangled name is between '(', and '+'.
        auto mangled_name = strings[i];
        auto left = std::strchr(mangled_name, '(');
        if (left == nullptr) {
            s += fmt::format("{}\n", strings[i]);
            continue;
        }

        left++;
        auto right = std::strchr(left, '+');
        if (right == nullptr || left == right) {
            s += fmt::format("{}\n", strings[i]);
            continue;
        }
        *right = '\0';

        /// Demangle the name.
        int status;
        size_t length = 1024;
        auto* ret = abi::__cxa_demangle(left, demangled_name, &length, &status);

        /// Append the demangled name if demangling succeeded.
        *right = '+';
        if (status == 0) {
            /// __cxa_demangle() may call realloc().
            demangled_name = ret;

            s.append(mangled_name, u64(left - mangled_name));
            s.append(demangled_name);
            s.append(right);
            s += '\n';
        } else s += fmt::format("{}\n", strings[i]);
    }

    free(strings);
    return s;
}

template <typename... args_t>
inline void err(fmt::format_string<args_t...> fmt_str, args_t&&... args) {
    fmt::print(log_stream, "\033[31m[{}] Error: ", current_time());
    fmt::print(log_stream, fmt_str, std::forward<args_t>(args)...);
#ifndef NDEBUG
    fmt::print(log_stream, "\n{}", current_stacktrace());
#endif
    fmt::print(log_stream, "\033[m\n");
}

template <typename... args_t>
[[noreturn]] inline void die(fmt::format_string<args_t...> fmt_str, args_t&&... args) {
    fmt::print(log_stream, "\033[1;31m[{}] Fatal: ", current_time());
    fmt::print(log_stream, fmt_str, std::forward<args_t>(args)...);
#ifndef NDEBUG
    fmt::print(log_stream, "\n{}", current_stacktrace());
#endif
    fmt::print(log_stream, "\033[m\n");
    std::exit(1);
}

template <typename... args_t>
[[noreturn]] void assertion_error(const std::string& cond_mess, const char* file, int line, const char* pretty_function, fmt::format_string<args_t...> fmt_str = "", args_t&&... args) {
    /// The extra \033[m may seem superfluous, but having them as extra delimiters
    /// makes translating the colour codes into html tags easier.
    if (isatty(fileno(log_stream))) {
        fmt::print(log_stream, "\033[1;31mAssertion Error\033[m\033[33m\n"
                               "    In internal file\033[m \033[32m{}:{}\033[m\033[33m\n"
                               "    In function\033[m \033[32m{}\033[m\033[33m\n"
                               "    Assertion failed:\033[m \033[34m{}",
                   file, line, pretty_function, cond_mess);
        auto str = fmt::format(fmt_str, std::forward<args_t>(args)...);
        if (!str.empty()) fmt::print(log_stream, "\033[m\n\033[33m    Message:\033[m \033[31m{}", str);

        fmt::print(log_stream, "\033[m\n");
    }

    else {
        fmt::print(log_stream, "Assertion Error\n"
                               "    In internal file {}:{}\n"
                               "    In function {}\n"
                               "    Assertion failed: {}\n",
                   file, line, pretty_function, cond_mess);
        auto str = fmt::format(fmt_str, std::forward<args_t>(args)...);
        if (!str.empty()) fmt::print(log_stream, "    Message: {}\n", str);
    }

    fmt::print(log_stream, "\033[33m    Stack trace:{}\n{}", isatty(fileno(log_stream)) ? "\033[m" : "", current_stacktrace());
    _Exit(1);
}

inline std::vector<char> map_file(std::string_view filename) {
    int fd = ::open(filename.data(), O_RDONLY);
    if (fd < 0) [[unlikely]]
        die("open(\"{}\") failed: {}", filename, ::strerror(errno));

    struct stat s {};
    if (::fstat(fd, &s)) [[unlikely]]
        die("fstat(\"{}\") failed: {}", filename, ::strerror(errno));
    auto sz = size_t(s.st_size);
    if (sz == 0) [[unlikely]]
        return {};

    auto* mem = (char*) ::mmap(nullptr, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) [[unlikely]]
        die("mmap(\"{}\", {}) failed: {}", filename, sz, ::strerror(errno));
    ::close(fd);

    std::vector<char> bytes(sz);
    std::memcpy(bytes.data(), mem, sz);
    if (::munmap(mem, sz)) [[unlikely]]
        die("munmap(\"{}\", {}) failed: {}", filename, sz, ::strerror(errno));
    return bytes;
}

struct require_operator_lhs {
    void operator%(bool rhs) { ASSERT(rhs); }
};
static inline require_operator_lhs require_operator_lhs_instance;

#define require require_operator_lhs_instance %

/// Encode a URL.
inline std::string encode_uri(std::string_view raw) {
    size_t start = 0;
    if (auto pos = raw.find("://")) start = pos + 3;

    std::string encoded;
    encoded.reserve(raw.size() * 3);
    for (size_t i = start; i < raw.size(); i++) {
        if (std::isalnum(raw[i]) || raw[i] == '-' || raw[i] == '_' || raw[i] == '.' || raw[i] == '~') encoded += raw[i];
        else {
            encoded += '%';
            encoded += fmt::format("{:02X}", u8(raw[i]));
        }
    }
    return encoded;
}

template <std::movable value_t>
struct generator {
    static_assert(!std::is_void_v<value_t>, "generator: template parameter must not be void");
    struct promise_type;

    /// Actual type of the generated values.
    using value_type = std::remove_cvref_t<value_t>;

    /// Reference/pointer to the value type.
    using reference = std::add_lvalue_reference_t<value_type>;
    using pointer = std::add_pointer_t<value_type>;

    /// Coroutine handle type.
    using handle_type = std::coroutine_handle<promise_type>;

    /// Coroutine promise type.
    struct promise_type {
        /// Value.
        value_type current_value;
        promise_type() = default;

        /// API.
        generator get_return_object() { return {handle_type::from_promise(*this)}; }
        std::suspend_always initial_suspend() { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }

        /// Disallow co_await.
        void await_transform() = delete;

        /// Rethrow exceptions.
        void unhandled_exception() { throw; }

        /// co_yield.
        std::suspend_always yield_value(std::convertible_to<value_type> auto&& res) {
            current_value = std::forward<decltype(res)>(res);
            return {};
        }

        /// co_return.
        void return_void() noexcept {}
    };

    /// Iterator to support range-based for loops.
    struct iterator {
        handle_type handle;

        iterator() : handle(nullptr) {}
        iterator(handle_type h) : handle(h) {}

        reference operator*() { return handle.promise().current_value; }
        pointer operator->() { return &handle.promise().current_value; }

        iterator& operator++() {
            handle.resume();
            return *this;
        }

        bool operator==(std::default_sentinel_t) {
            return !handle || handle.done();
        }
    };

private:
    /// Coroutine handle.
    handle_type handle;
public:

    /// Set the handle.
    generator(handle_type h) : handle(h) {}

    /// Copying coroutines is nonsense.
    generator(const generator&) = delete;
    generator& operator=(const generator&) = delete;

    /// Moving is ok.
    generator(generator&& other) noexcept : handle(other.handle) { other.handle = nullptr; }
    generator& operator=(generator&& other) noexcept {
        if (handle) handle.destroy();
        handle = other.handle;
        other.handle = nullptr;
    }

    /// Cleanup.
    ~generator() {
        if (handle) handle.destroy();
    }

    /// Advance the coroutine and return the current value.
    /// Be careful when using this since there's no way to check if the coroutine is done.
    reference operator()() {
        handle.resume();
        return handle.promise().current_value;
    }

    iterator begin() { handle.resume(); return {handle}; }
    std::default_sentinel_t end() { return {}; }
};

using resumable = generator<bool>;

#define YIELD_INCOMPLETE() \
    do {                   \
        co_yield false;    \
    } while (0)

#define YIELD_SUCCESS() \
    do {                \
        co_yield true;  \
        co_return;      \
    } while (0)

/// Convert a string to lowercase.
inline std::string tolower(std::string_view str) {
    std::string res;
    res.resize(str.size());
    std::ranges::transform(str, res.begin(), [](char c) { return std::tolower(c); });
    return res;
}

/// Enum arithmetic.
#define ENUM_OPERATOR(op)                                                                                    \
    template <typename enumeration, typename integer>                                                        \
        requires(std::is_enum_v<enumeration> && std::is_integral_v<integer>)                                 \
    constexpr integer operator op(enumeration lhs, integer rhs) { return static_cast<integer>(lhs) op rhs; } \
                                                                                                             \
    template <typename integer, typename enumeration>                                                        \
        requires(std::is_enum_v<enumeration> && std::is_integral_v<integer>)                                 \
    constexpr integer operator op(integer lhs, enumeration rhs) { return lhs op static_cast<integer>(rhs); } \
                                                                                                             \
    template <typename enum1, typename enum2>                                                                \
        requires(std::is_enum_v<enum1> && std::is_same_v<enum1, enum2>)                                      \
    constexpr std::underlying_type_t<enum1> operator op(enum1 lhs, enum2 rhs) {                              \
        using integer = std::underlying_type_t<enum1>;                                                       \
        return static_cast<integer>(lhs) op static_cast<integer>(rhs);                                       \
    }

template <typename enumeration>
    requires std::is_enum_v<enumeration>
constexpr std::underlying_type_t<enumeration> operator~(enumeration e) {
    return compl static_cast<std::underlying_type_t<enumeration>>(e);
}

ENUM_OPERATOR(+)
ENUM_OPERATOR(-)
ENUM_OPERATOR(&)
ENUM_OPERATOR(|)

#endif // NET_UTILS_HH
