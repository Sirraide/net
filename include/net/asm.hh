#ifndef NET_ASM_HH
#define NET_ASM_HH

#include <cstdint>

namespace net::detail {
/// XOR a region of memory with a 32-bit value.
void memxor32(void* ptr, std::size_t size, int mask);
} // namespace net::detail

#endif // NET_ASM_HH
