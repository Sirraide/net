#ifndef NET_ASM_HH
#define NET_ASM_HH

#include <cstdint>

#ifdef __AVX2__
#    include <immintrin.h>
#endif

#ifdef __SSE2__
#    include <emmintrin.h>
#endif

#ifdef __MMX__
#    include <mmintrin.h>
#endif

namespace net::detail {

/// XOR a region of memory with a 32-bit value.
void memxor32(uint8_t* data, std::size_t size, int mask) {
    std::size_t i = 0;

    /// Align the pointer to a 32-bit boundary.
    while (i < size and (reinterpret_cast<uintptr_t>(data) + i) & 3) {
        data[i] ^= reinterpret_cast<uint8_t*>(&mask)[i % 4];
        i++;
    }

    /// Align to a 64-bit boundary.
#ifdef __MMX__
    if (i < size and (reinterpret_cast<uintptr_t>(data) + i) & 7) {
        *reinterpret_cast<uint32_t*>(data + i) ^= mask;
        i += 4;
    }
#endif

    /// Align to a 128-bit boundary.
#ifdef __SSE2__
    if (i < size and (reinterpret_cast<uintptr_t>(data) + i) & 15) {
        auto* ptr = reinterpret_cast<__m64*>(data + i);
        *ptr = _mm_xor_si64(*ptr, _mm_set1_pi32(mask));
        i += 8;
    }
#endif

    /// Align to a 256-bit boundary.
#ifdef __AVX2__
    if (i < size and (reinterpret_cast<uintptr_t>(data) + i) & 31) {
        auto* ptr = reinterpret_cast<__m128i*>(data + i);
        *ptr = _mm_xor_si128(*ptr, _mm_set1_epi32(mask));
        i += 16;
    }
#endif

    /// Align to a 512-bit boundary and XOR 512-bit blocks.
#ifdef __AVX512F__
    if (i < size and (reinterpret_cast<uintptr_t>(data) + i) & 63) {
        auto* ptr = reinterpret_cast<__m256i*>(data + i);
        *ptr = _mm256_xor_si256(*ptr, _mm256_set1_epi32(mask));
        i += 32;
    }

    while (i + 64 <= size) {
        auto* ptr = reinterpret_cast<__m512i*>(data + i);
        *ptr = _mm512_xor_si512(*ptr, _mm512_set1_epi32(mask));
        i += 64;
    }
#endif

    /// XOR 256-bit blocks.
#ifdef __AVX2__
    while (i + 32 <= size) {
        auto* ptr = reinterpret_cast<__m256i*>(data + i);
        *ptr = _mm256_xor_si256(*ptr, _mm256_set1_epi32(mask));
        i += 32;
    }
#endif

    /// XOR 128-bit blocks.
#ifdef __SSE2__
    while (i + 16 <= size) {
        auto* ptr = reinterpret_cast<__m128i*>(data + i);
        *ptr = _mm_xor_si128(*ptr, _mm_set1_epi32(mask));
        i += 16;
    }
#endif

    /// XOR 64-bit blocks.
#ifdef __MMX__
    while (i + 8 <= size) {
        auto* ptr = reinterpret_cast<__m64*>(data + i);
        *ptr = _mm_xor_si64(*ptr, _mm_set1_pi32(mask));
        i += 8;
    }
#endif

    /// XOR 4 bytes at a time.
    while (i + 4 <= size) {
        *reinterpret_cast<uint32_t*>(data + i) ^= mask;
        i += 4;
    }

    /// XOR the remaining bytes.
    while (i < size) {
        data[i] ^= reinterpret_cast<uint8_t*>(&mask)[i % 4];
        i++;
    }
}

} // namespace net::detail

#endif // NET_ASM_HH
