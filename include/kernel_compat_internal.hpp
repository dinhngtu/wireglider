#pragma once

#include <algorithm>
#include <cstring>
#include <atomic>
#include <pthread.h>
#include "kernel_compat.hpp"

#define __force
#define __must_check
#define might_alloc(x)

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define IS_ALIGNED(x, a) (((x) & ((decltype(x))(a) - 1)) == 0)

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif

#define likely(x) x
#define unlikely(x) x

#define MAX_ERRNO 4095

#define BITS_PER_BYTE 8
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BITS_PER_LONG (BITS_PER_TYPE(long))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_TYPE(long))

static_assert(BITS_PER_LONG == 64);
#define _BITOPS_LONG_SHIFT 6

#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)

#define BITMAP_MEM_ALIGNMENT 8
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)

#define RLONG_ADDR(x) "m"(*(volatile long *)(x))
#define WBYTE_ADDR(x) "+m"(*(volatile char *)(x))

#define ADDR RLONG_ADDR(addr)

static __always_inline bool constant_test_bit(long nr, const volatile unsigned long *addr) {
    return ((1UL << (nr & (BITS_PER_LONG - 1))) & (addr[nr >> _BITOPS_LONG_SHIFT])) != 0;
}

static __always_inline bool variable_test_bit(long nr, volatile const unsigned long *addr) {
    bool oldbit;

    asm volatile("btrq %2,%1" : "=@ccc"(oldbit) : "m"(*(unsigned long *)addr), "Ir"(nr) : "memory");

    return oldbit;
}

static __always_inline bool _test_bit(unsigned long nr, const volatile unsigned long *addr) {
    return __builtin_constant_p(nr) ? constant_test_bit(nr, addr) : variable_test_bit(nr, addr);
}

static __always_inline bool const_test_bit(unsigned long nr, const volatile unsigned long *addr) {
    const unsigned long *p = (const unsigned long *)addr + BIT_WORD(nr);
    unsigned long mask = BIT_MASK(nr);
    unsigned long val = *p;

    return !!(val & mask);
}

static __always_inline bool __test_and_set_bit(unsigned long nr, volatile unsigned long *addr) {
    bool oldbit;

    asm("btsq %2,%1" : "=@ccc"(oldbit) : ADDR, "Ir"(nr) : "memory");
    return oldbit;
}

static __always_inline bool __test_and_clear_bit(unsigned long nr, volatile unsigned long *addr) {
    bool oldbit;

    asm volatile("btrq %2,%1" : "=@ccc"(oldbit) : ADDR, "Ir"(nr) : "memory");
    return oldbit;
}

static __always_inline void __set_bit(unsigned long nr, volatile unsigned long *addr) {
    asm volatile("btsq %1,%0" : : ADDR, "Ir"(nr) : "memory");
}

static __always_inline void __clear_bit(unsigned long nr, volatile unsigned long *addr) {
    asm volatile("btrq %1,%0" : : ADDR, "Ir"(nr) : "memory");
}

static __always_inline unsigned long _variable__ffs(unsigned long word) {
    asm("rep; bsf %1,%0" : "=r"(word) : "rm"(word));
    return word;
}

#define bitop(op, nr, addr)                                                                         \
    ((__builtin_constant_p(nr) && __builtin_constant_p((uintptr_t)(addr) != (uintptr_t)NULL) &&     \
      (uintptr_t)(addr) != (uintptr_t)NULL && __builtin_constant_p(*(const unsigned long *)(addr))) \
         ? const##op(nr, addr)                                                                      \
         : op(nr, addr))

#define test_bit(nr, addr) bitop(_test_bit, nr, addr)

/**
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
#define __ffs(word) (__builtin_constant_p(word) ? (unsigned long)__builtin_ctzl(word) : _variable__ffs(word))

#define small_const_nbits(nbits) (__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG && (nbits) > 0)

#define GENMASK_INPUT_CHECK(h, l) 0

#define __GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK(h, l) (GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

#define FIND_FIRST_BIT(FETCH, MUNGE, size)                                  \
    ({                                                                      \
        unsigned long idx, val, sz = (size);                                \
                                                                            \
        for (idx = 0; idx * BITS_PER_LONG < sz; idx++) {                    \
            val = (FETCH);                                                  \
            if (val) {                                                      \
                sz = std::min(idx * BITS_PER_LONG + __ffs(MUNGE(val)), sz); \
                break;                                                      \
            }                                                               \
        }                                                                   \
                                                                            \
        sz;                                                                 \
    })

#define FIND_NEXT_BIT(FETCH, MUNGE, size, start)                      \
    ({                                                                \
        unsigned long mask, idx, tmp, sz = (size), __start = (start); \
                                                                      \
        if (unlikely(__start >= sz))                                  \
            goto out;                                                 \
                                                                      \
        mask = MUNGE(BITMAP_FIRST_WORD_MASK(__start));                \
        idx = __start / BITS_PER_LONG;                                \
                                                                      \
        for (tmp = (FETCH) & mask; !tmp; tmp = (FETCH)) {             \
            if ((idx + 1) * BITS_PER_LONG >= sz)                      \
                goto out;                                             \
            idx++;                                                    \
        }                                                             \
                                                                      \
        sz = std::min(idx * BITS_PER_LONG + __ffs(MUNGE(tmp)), sz);   \
    out:                                                              \
        sz;                                                           \
    })

unsigned long _find_next_bit(const unsigned long *addr, unsigned long nbits, unsigned long start);

unsigned long _find_first_bit(const unsigned long *addr, unsigned long size);

static inline unsigned long find_first_bit(const unsigned long *addr, unsigned long size) {
    if (small_const_nbits(size)) {
        unsigned long val = *addr & GENMASK(size - 1, 0);

        return val ? __ffs(val) : size;
    }

    return _find_first_bit(addr, size);
}

static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset) {
    if (small_const_nbits(size)) {
        unsigned long val;

        if (unlikely(offset >= size))
            return size;

        val = *addr & GENMASK(size - 1, offset);
        return val ? __ffs(val) : size;
    }

    return _find_next_bit(addr, size, offset);
}

static inline void bitmap_fill(unsigned long *dst, unsigned int nbits) {
    unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);

    if (small_const_nbits(nbits))
        *dst = ~0UL;
    else
        memset(dst, 0xff, len);
}

static inline bool bitmap_empty(const unsigned long *src, unsigned nbits) {
    if (small_const_nbits(nbits))
        return !(*src & BITMAP_LAST_WORD_MASK(nbits));

    return find_first_bit(src, nbits) == nbits;
}

void __bitmap_clear(unsigned long *map, unsigned int start, int len);

static __always_inline void bitmap_clear(unsigned long *map, unsigned int start, unsigned int nbits) {
    if (__builtin_constant_p(nbits) && nbits == 1)
        __clear_bit(start, map);
    else if (small_const_nbits(start + nbits))
        *map &= ~GENMASK(start + nbits - 1, start);
    else if (
        __builtin_constant_p(start & BITMAP_MEM_MASK) && IS_ALIGNED(start, BITMAP_MEM_ALIGNMENT) &&
        __builtin_constant_p(nbits & BITMAP_MEM_MASK) && IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
        memset((char *)map + start / 8, 0, nbits / 8);
    else
        __bitmap_clear(map, start, nbits);
}

#define RCU_INIT_POINTER(p, v) rcu_assign_pointer(p, v)

static __always_inline void smp_wmb() {
    std::atomic_thread_fence(std::memory_order_acq_rel);
}

static __always_inline void smp_rmb() {
    std::atomic_thread_fence(std::memory_order_acq_rel);
}

#define __must_hold(x)
#define __init
#define gfpflags_allow_blocking(x) 0

#define ARRAY_SIZE(ar) (sizeof(ar) / sizeof(ar[0]))

#define lockdep_is_held(x) 1

#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough \
    do {            \
    } while (0) /* fallthrough */
#endif

template <typename T>
static constexpr T min(T a, T b) {
    return std::min(a, b);
}

template <typename T>
static constexpr T max(T a, T b) {
    return std::max(a, b);
}

#define new _new

#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)

#define rcu_dereference_protected(a, b) rcu_dereference(a)
#define rcu_dereference_check(a, b) rcu_dereference(a)

#define trace_ma_op(x, y)
#define trace_ma_read(x, y)
#define trace_ma_write(x, y, z, t)

#include "gfp_types.h"
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))

#define IS_ENABLED(x) x
#define CONFIG_LOCKDEP 0
