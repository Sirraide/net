#ifndef NET_COMMON_HH
#define NET_COMMON_HH

#include "utils.hh"

#include <cstdint>
#include <span>
#include <vector>

namespace net {
/// Helper to facilitate receiving data incrementally into a single buffer.
class recvbuffer {
    u8* bytes{};
    u64 sz{};
    u64 cap{};
    u64 offset{};

public:
    /// This is so we can have type checking of absolute vs relative offsets.
    enum struct absolute : u64 {};

    recvbuffer() = default;
    ~recvbuffer() { std::free(bytes); }

    /// The whole point of this is that we *don't* want to copy data unnecessarily,
    /// so we delete the copy constructor to prevent that from happening accidentally.
    nocopy(recvbuffer);

    /// Move constructor.
    recvbuffer(recvbuffer&& other) noexcept { *this = std::move(other); }
    recvbuffer& operator=(recvbuffer&& other) noexcept {
        if (this == std::addressof(other)) return *this;
        std::free(bytes);
        bytes = other.bytes;
        sz = other.sz;
        cap = other.cap;
        offset = other.offset;
        other.bytes = nullptr;
        other.sz = 0;
        other.cap = 0;
        other.offset = 0;
        return *this;
    }

    /// Allocate more space in the buffer.
    void allocate(u64 size) {
        if (size > cap) {
            bytes = (u8*) std::realloc(bytes, size);
            if (not bytes) throw std::bad_alloc();
            cap = size;
        }
        sz = size;
     }

    /// Clear the buffer.
    void clear() {
        sz = 0;
        offset = 0;
    }

    /// Erase data at an absolute offset.
    void erase(absolute start, u64 elems) {
        auto st = u64(start);
        auto size = std::min(elems, sz - st);
        if (st >= sz) throw std::runtime_error("recvbuffer::erase() out of bounds");

        std::memmove(bytes + st, bytes + st + size, sz - st - size);
        sz -= size;
        if (offset > st) offset = std::max(st, offset - size);
    }

    /// Erase data up to the current offset.
    void erase_to_offset(absolute start = absolute(0)) { erase(start, offset); }

    /// Resize the buffer.
    void grow(u64 newsz) { sz = newsz; }

    /// Extract data from the buffer and skip past it.
    template <typename type>
    [[nodiscard, gnu::always_inline]] type& extract() {
        auto* result = reinterpret_cast<type*>(data());
        offset += sizeof(type);
        return *result;
    }

    /// Set the offset.
    void offs(absolute off) { offset = u64(off); }

    /// Reset the offset to the beginning of the buffer.
    void reset() { offset = 0; }

    /// Skip past some data.
    void skip(u64 elems) { offset += std::min(elems, size()); }

    [[nodiscard]] absolute offs() const { return absolute(offset); }
    [[nodiscard]] u8* data() { return bytes + offset; }
    [[nodiscard]] const u8* data() const { return bytes + offset; }
    [[nodiscard]] size_t size() const { return sz - offset; }
    [[nodiscard]] size_t capacity() const { return cap - offset; }

    [[nodiscard]] bool empty() const { return sz <= offset; }

    [[nodiscard]] u8& operator[](size_t i) { return bytes[offset + i]; }
    [[nodiscard]] const u8& operator[](size_t i) const { return bytes[offset + i]; }

    [[nodiscard]] auto begin() { return data(); }
    [[nodiscard]] auto end() { return bytes + sz; }
    [[nodiscard]] auto begin() const { return data(); }
    [[nodiscard]] auto end() const { return bytes + sz; }

    [[nodiscard]] auto cbegin() const { return begin(); }
    [[nodiscard]] auto cend() const { return end(); }

    [[nodiscard]] std::span<u8> span() { return {data(), size()}; }
    [[nodiscard]] std::span<const u8> span() const { return {data(), size()}; }
};
} // namespace net

#endif // NET_COMMON_HH
