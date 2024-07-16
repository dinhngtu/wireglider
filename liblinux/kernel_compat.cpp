#include <string>
#include <fmt/format.h>
#include "liblinux/kernel_compat_internal.hpp"

bool _do_warn(bool val, const char *warn) {
    if (val)
        fmt::print("WARN: {}", warn);
    return val;
}

bool _do_bug(bool val, const char *bug) {
    if (val)
        throw std::runtime_error(bug);
    return val;
}

void __bitmap_clear(unsigned long *map, unsigned int start, int len) {
    unsigned long *p = map + BIT_WORD(start);
    const unsigned int size = start + len;
    int bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
    unsigned long mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

    while (len - bits_to_clear >= 0) {
        *p &= ~mask_to_clear;
        len -= bits_to_clear;
        bits_to_clear = BITS_PER_LONG;
        mask_to_clear = ~0UL;
        p++;
    }
    if (len) {
        mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
        *p &= ~mask_to_clear;
    }
}

unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start) {
    return FIND_NEXT_BIT(addr[idx], /* nop */, nbits, start);
}

unsigned long _find_first_bit(const unsigned long *addr, unsigned long size) {
    return FIND_FIRST_BIT(addr[idx], /* nop */, size);
}
