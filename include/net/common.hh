#ifndef NET_COMMON_HH
#define NET_COMMON_HH

#include "utils.hh"

#include <cstdint>
#include <span>
#include <vector>

namespace net {
/// \brief Incremental receive buffer that supports extracting data without truncating the buffer.
///
/// This class is used by the implementation to receive data from the network.
/// It is somewhat of a cross between a \c std::vector and a \c std::span or
/// \c std::string_view in that it supports both automatic resizing and allocation
/// as well as truncation and extraction of data without affecting the underlying
/// data.
///
/// The buffer internally maintains an \c offset that is treated as the logical
/// start of the buffer. For example, when the size of the buffer is queried, it
/// will return the size of the underlying buffer minus the offset.
///
/// The functions \c extract() and \c try_extract() are used to extract data from
/// the buffer. Both functions will advance the offset by the size of the data
/// extracted. The data is still in the underlying buffer, but logically, it has
/// been erased from the buffer.
///
/// See the documentation of individual functions below for more information.
class recvbuffer {
    char* bytes{};
    u64 sz{};
    u64 cap{};
    u64 offset{};

public:
    /// Helper type to enable type checking of absolute vs relative offsets.
    enum struct absolute : u64 {};

    /// Construct an empty buffer.
    recvbuffer() = default;

    /// Destroy the buffer and free associated memory.
    ~recvbuffer() { std::free(bytes); }

    /// The whole point of this is that we *don't* want to copy data unnecessarily,
    /// so we delete the copy constructor to prevent that from happening accidentally.
    recvbuffer(const recvbuffer&) = delete;
    recvbuffer& operator=(const recvbuffer&) = delete;

    /// Move constructor. This does exactly what you think it does.
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
    ///
    /// Despite the name, this function does not necessarily allocate more space.
    /// If the buffer already has enough space to hold the requested number of
    /// bytes, this function will return immediately.
    ///
    /// \param size The number of additional bytes to allocate.
    void allocate(u64 size) {
        if (size > capacity()) {
            cap = std::max(cap * 2, size);
            bytes = (char*) std::realloc(bytes, cap);
            if (not bytes) throw std::bad_alloc();
        }
     }

    /// Clear the buffer.
    ///
    /// This erases *all* data from the underlying buffer. The offset is reset to
    /// zero and the size is set to zero. The capacity is not changed.
    void clear() {
        sz = 0;
        offset = 0;
    }

    /// \brief Erase data at an absolute offset.
    ///
    /// Unlike \c extract() or \c skip(), this function erases data directly from the
    /// underlying buffer.
    ///
    /// Most of the time, you probably want to use \c erase_to_offset() instead.
    ///
    /// \param start An absolute offset into the buffer that indicates where to
    ///     start erasing, preferably obtained from \c offs().
    /// \param elems The number of elements to erase.
    void erase(absolute start, u64 elems) {
        auto st = u64(start);
        auto size = std::min(elems, sz - st);
        if (st >= sz) throw std::runtime_error("recvbuffer::erase() out of bounds");

        std::memmove(bytes + st, bytes + st + size, sz - st - size);
        sz -= size;
        if (offset > st) offset = std::max(st, offset - size);
    }

    /// \brief Erase data up to the current offset.
    ///
    /// This function erases all data from the underlying buffer up to the current
    /// offset. This is useful when you want to discard all data that has already been
    /// processed since the last call to \c offs().
    ///
    /// Example:
    /// ```
    /// auto start = buf.offs();
    /// // receive and process data ...
    /// buf.erase(start);
    /// ```
    /// \param start An absolute offset into the buffer that indicates where to
    ///     start erasing, preferably obtained from \c offs(). If no argument is
    ///     provided, all data starting from the beginning of the underlying buffer
    ///     is erased.
    void erase_to_offset(absolute start = absolute(0)) { erase(start, offset); }

    /// \brief Increase the logical size of the buffer.
    ///
    /// This function does *not* allocate any memory; (use \c allocate() for that
    /// instead) it is meant to be used after data has been received into the buffer
    /// to tell the buffer how much data has been received.
    ///
    /// Example:
    /// ```
    /// // Receive data into the buffer.
    /// recvbuffer buf;
    /// buf.allocate(1024);
    /// auto n = recv(sock, buf.data(), buf.capacity());
    /// buf.grow(n); // Tell the buffer that it now contains n bytes.
    /// ```
    ///
    /// \param nbytes How much to increase the size of the buffer by.
    /// \throw std::runtime_error If the new size of the buffer would exceed its capacity.
    void grow(u64 nbytes) {
        if (nbytes > capacity()) throw std::runtime_error(fmt::format("recvbuffer::grow({}) out of bounds. Offset is {}. Capacity is {}", nbytes, offset, cap));
        sz += nbytes;
    }

    /// \brief Extract data from the buffer and skip past it.
    ///
    /// This casts the beginning of the buffer to the specified type and returns
    /// a reference to it. This is used to extract data from the buffer without
    /// copying it. The buffer is then advanced by the size of the type. This way
    /// multiple elements can be extracted from the buffer in succession by performing
    /// repeated calls to \c extract().
    ///
    /// This function does not perform any bounds checking. If the buffer is not
    /// large enough to contain the requested type, the behavior is undefined.
    ///
    /// If you are not sure that the buffer contains enough data to extract the
    /// requested type, use \c try_extract() instead.
    ///
    /// Example:
    /// ```
    /// // Receive and extract a 64-bit integer from the buffer.
    /// recvbuffer buf;
    /// buf.allocate(1024);
    /// conn.recv(buffer, sizeof(u64));
    /// u64& val = buf.extract<u64>();
    /// ```
    ///
    /// \see try_extract()
    ///
    /// \tparam type The type of data to extract.
    /// \return A reference to the beginning of the buffer, cast to the type
    ///     specified by \c type.
    template <typename type>
    [[nodiscard, gnu::always_inline]] type& extract() {
        auto* result = reinterpret_cast<type*>(data());
        offset += sizeof(type);
        return *result;
    }

    /// \brief Try to extract data from the buffer and skip past it.
    ///
    /// This function is the same as \c extract(), except that is checks that
    /// there is enough data in the buffer to extract the specified type. If
    /// there is not enough data, then the buffer is not advanced and the
    /// function returns \c nullptr.
    ///
    /// If you are certain that the buffer contains enough data to extract the
    /// requested type, use \c extract() instead.
    ///
    /// Example:
    /// ```
    /// // Try extracting a 64-bit integer from the buffer and print it if successful.
    /// recvbuffer buf;
    /// buf.allocate(1024);
    /// conn.recv(buffer, 0); // Receive any amount of bytes.
    /// if (u64* val = buf.try_extract<u64>(); val) fmt::print("Received: {}\n", *val);
    /// ```
    ///
    /// \see extract()
    ///
    /// \tparam type The type of data to extract.
    /// \return A pointer to the beginning of the buffer, cast to the type
    ///     specified by \c type, or \c nullptr if there is not enough data
    ///     in the buffer to extract the type.
    template <typename type>
    [[nodiscard, gnu::always_inline]] type* try_extract() {
        if (offset + sizeof(type) > sz) return nullptr;
        auto* result = reinterpret_cast<type*>(data());
        offset += sizeof(type);
        return result;
    }

    /// Set the current offset.
    ///
    /// \param off The new absolute offset, preferably obtained from \c offs().
    void offs(absolute off) { offset = u64(off); }

    /// Reset the offset to the beginning of the buffer.
    void reset() { offset = 0; }

    /// \brief Skip past some data.
    ///
    /// This function does *not* erase any data from the underlying buffer; instead
    /// it simply advances the offset by the specified number of bytes.
    ///
    /// \param nbytes The number of bytes to skip past.
    void skip(u64 nbytes) { offset += std::min(nbytes, size()); }

    /// Return the current absolute offset.
    [[nodiscard]] absolute offs() const { return absolute(offset); }

    /// Get a pointer to the logical beginning of the buffer.
    [[nodiscard]] char* data() { return bytes + offset; }

    /// Get a pointer to the logical beginning of the buffer.
    [[nodiscard]] const char* data() const { return bytes + offset; }

    /// Get the logical size of the buffer.
    [[nodiscard]] size_t size() const { return sz - offset; }

    /// Get the logical capacity of the buffer.
    [[nodiscard]] size_t capacity() const { return cap - offset; }

    /// Check whether the buffer is empty.
    [[nodiscard]] bool empty() const { return sz <= offset; }

    /// Access the byte at \c offset + i.
    [[nodiscard]] char& operator[](size_t i) { return bytes[offset + i]; }

    /// Access the byte at \c offset + i.
    [[nodiscard]] const char& operator[](size_t i) const { return bytes[offset + i]; }

    [[nodiscard]] auto begin() { return data(); }
    [[nodiscard]] auto end() { return bytes + sz; }
    [[nodiscard]] auto begin() const { return data(); }
    [[nodiscard]] auto end() const { return bytes + sz; }

    [[nodiscard]] auto cbegin() const { return begin(); }
    [[nodiscard]] auto cend() const { return end(); }

    /// Get a span of the data in the buffer.
    [[nodiscard]] std::span<char> span() { return {data(), size()}; }

    /// Get a span of the data in the buffer.
    [[nodiscard]] std::span<const char> span() const { return {data(), size()}; }

    /// Get a \c std::string_view of the data in the buffer.
    [[nodiscard]] std::string_view str() const { return {data(), size()}; }

    /// Get a span of \c u8 of the data in the buffer.
    [[nodiscard]] std::span<uint8_t> u8() { return {reinterpret_cast<uint8_t*>(data()), size()}; }

    /// Get a span of \c u8 of the data in the buffer.
    [[nodiscard]] std::span<const uint8_t> u8() const { return {reinterpret_cast<const uint8_t*>(data()), size()}; }
};
} // namespace net

#endif // NET_COMMON_HH
