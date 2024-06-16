#pragma once

#include <cstdint>
#include <span>

#ifdef USE_ADX
extern "C" uint64_t checksum_raw_nofold_x64(const uint8_t *ptr, size_t size, uint64_t initial);
#endif

namespace wgss {

namespace checksum_impl {

template <typename T>
static inline T addc_fallback(T a, T b, T cin, T *cout) {
    T s;
    bool c1 = __builtin_add_overflow(a, b, &s);
    bool c2 = __builtin_add_overflow(s, cin, &s);
    *cout = c1 | c2;
    return s;
}

static inline unsigned int addc(unsigned int a, unsigned int b, unsigned int cin, unsigned int *cout) {
#if __has_builtin(__builtin_addc)
    return __builtin_addc(a, b, cin, cout);
#else
    return addc_fallback(a, b, cin, cout);
#endif
}

static inline unsigned long int addc(
    unsigned long int a,
    unsigned long int b,
    unsigned long int cin,
    unsigned long int *cout) {
#if __has_builtin(__builtin_addcl)
    return __builtin_addcl(a, b, cin, cout);
#else
    return addc_fallback(a, b, cin, cout);
#endif
}

static inline unsigned long long int addc(
    unsigned long long int a,
    unsigned long long int b,
    unsigned long long int cin,
    unsigned long long int *cout) {
#if __has_builtin(__builtin_addcll)
    return __builtin_addcll(a, b, cin, cout);
#else
    return addc_fallback(a, b, cin, cout);
#endif
}

template <typename T>
static inline uint64_t checksum_add(const T val, uint64_t initial) {
    uint64_t ret;
    bool c = __builtin_add_overflow(initial, static_cast<uint64_t>(val), &ret);
    return ret + c;
}

static inline uint64_t checksum_nofold(std::span<const uint8_t, 16> b, uint64_t initial) {
    uint64_t carry = 0;
    uint64_t ac = checksum_impl::addc(initial, *reinterpret_cast<const uint64_t *>(&b[0]), 0, &carry);
    ac = checksum_impl::addc(ac, *reinterpret_cast<const uint64_t *>(&b[8]), carry, &carry);
    ac += carry;
    return ac;
}

static inline uint64_t checksum_nofold(std::span<const uint8_t, 8> b, uint64_t initial) {
    uint64_t ret;
    bool c = __builtin_add_overflow(initial, *reinterpret_cast<const uint64_t *>(&b[0]), &ret);
    return ret + c;
}

static inline uint64_t checksum_nofold(std::span<const uint8_t, 4> b, uint64_t initial) {
    uint64_t ret;
    bool c = __builtin_add_overflow(initial, static_cast<uint64_t>(*reinterpret_cast<const uint32_t *>(&b[0])), &ret);
    return ret + c;
}

static inline uint64_t checksum_nofold(std::span<const uint8_t, 2> b, uint64_t initial) {
    uint64_t ret;
    bool c = __builtin_add_overflow(initial, static_cast<uint64_t>(*reinterpret_cast<const uint16_t *>(&b[0])), &ret);
    return ret + c;
}

static inline uint64_t checksum_nofold(std::span<const uint8_t, 1> b, uint64_t initial) {
    uint64_t carry = 0;
    uint64_t ac = checksum_impl::addc(initial, static_cast<uint64_t>(b[0]), 0, &carry);
    ac += carry;
    return ac;
}

uint64_t checksum_nofold_generic(std::span<const uint8_t, std::dynamic_extent> b, uint64_t initial);

#ifdef USE_ADX
static inline uint64_t checksum_nofold(std::span<const uint8_t, std::dynamic_extent> b, uint64_t initial) {
    return checksum_raw_nofold_x64(b.data(), b.size(), initial);
}
#else
// use the generic implementation
static inline uint64_t checksum_nofold(std::span<const uint8_t, std::dynamic_extent> b, uint64_t initial) {
    return checksum_nofold_generic(b, initial);
}
#endif

static inline uint16_t fold_complement_checksum(uint64_t initial) {
    uint32_t ac32;
    bool c1 = __builtin_add_overflow(
        static_cast<uint32_t>(initial >> 32),
        static_cast<uint32_t>(initial & 0xffffffff),
        &ac32);
    ac32 += c1;

    uint16_t ac16;
    bool c2 = __builtin_add_overflow(static_cast<uint16_t>(ac32 >> 16), static_cast<uint16_t>(ac32 & 0xffff), &ac16);
    ac16 += c2;

    return ~ac16;
}

template <size_t E1, size_t E2>
static inline uint64_t pseudo_header_checksum_nofold(
    uint8_t proto,
    std::span<const uint8_t, E1> srcAddr,
    std::span<const uint8_t, E2> dstAddr,
    uint16_t totalLen) {
    auto sum = checksum_impl::checksum_nofold(srcAddr, 0);
    sum = checksum_impl::checksum_nofold(dstAddr, sum);
    sum = checksum_impl::checksum_add(proto, sum);
    sum = checksum_impl::checksum_add(totalLen, sum);
    return sum;
}

} // namespace checksum_impl

template <size_t E1, size_t E2>
static inline uint16_t pseudo_header_checksum(
    uint8_t proto,
    std::span<const uint8_t, E1> srcAddr,
    std::span<const uint8_t, E2> dstAddr,
    uint16_t totalLen) {
    auto ac = checksum_impl::pseudo_header_checksum_nofold(proto, srcAddr, dstAddr, totalLen);
    return checksum_impl::fold_complement_checksum(ac);
}

static inline uint16_t checksum(std::span<const uint8_t> b, uint64_t initial) {
    auto ac = checksum_impl::checksum_nofold(b, initial);
    return checksum_impl::fold_complement_checksum(ac);
}

} // namespace wgss
