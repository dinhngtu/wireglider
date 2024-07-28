#pragma once

// useful references:
// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/checksum.go
// https://blogs.igalia.com/dpino/2018/06/14/fast-checksum-computation
// https://github.com/snabbco/snabb/commit/0068df61213d030ac6064f0d5db8705373e7e3c7

#include <cstdint>
#include <cstring>
#include <span>
#include <array>
#include <boost/endian.hpp>

#include <fastcsum.h>

namespace wireglider {

namespace checksum_impl {

template <typename T>
static inline uint64_t checksum_add(const T val, uint64_t initial) {
    uint64_t ret = initial;
    bool c = __builtin_add_overflow(ret, static_cast<uint64_t>(val), &ret);
    return ret + c;
}

template <size_t N>
static inline uint64_t checksum_nofold(std::span<const uint8_t, N> b, uint64_t initial);

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, 16> b, uint64_t initial) {
    uint64_t ret = initial;
    uint64_t tmp;
    memcpy(&tmp, &b[0], sizeof(tmp));
    bool c1 = __builtin_add_overflow(ret, tmp, &ret);
    ret += c1;
    memcpy(&tmp, &b[8], sizeof(tmp));
    bool c2 = __builtin_add_overflow(ret, tmp, &ret);
    return ret + c2;
}

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, 8> b, uint64_t initial) {
    uint64_t ret = initial;
    uint64_t tmp;
    memcpy(&tmp, &b[0], sizeof(tmp));
    bool c = __builtin_add_overflow(ret, tmp, &ret);
    return ret + c;
}

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, 4> b, uint64_t initial) {
    uint64_t ret = initial;
    uint32_t tmp;
    memcpy(&tmp, &b[0], sizeof(tmp));
    bool c = __builtin_add_overflow(ret, static_cast<uint64_t>(tmp), &ret);
    return ret + c;
}

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, 2> b, uint64_t initial) {
    uint64_t ret = initial;
    uint16_t tmp;
    memcpy(&tmp, &b[0], sizeof(tmp));
    bool c = __builtin_add_overflow(ret, static_cast<uint64_t>(tmp), &ret);
    return ret + c;
}

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, 1> b, uint64_t initial) {
    uint64_t ret = initial;
    uint64_t last = b[0];
    if (__BYTE_ORDER == __BIG_ENDIAN)
        last <<= 8;
    bool c = __builtin_add_overflow(ret, last, &ret);
    return ret + c;
}

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, std::dynamic_extent> b, uint64_t initial) {
#if defined(__ADX__)
    static const size_t vector_threshold = 1024;
#else
    static const size_t vector_threshold = 512;
#endif
#if defined(__AVX2__)
    if (b.size() > vector_threshold)
        return fastcsum_nofold_vec256_align(b.data(), b.size(), initial);
#elif defined(__AVX__) || defined(__SSE4_1__)
    if (b.size() > vector_threshold)
        return fastcsum_nofold_vec128_align(b.data(), b.size(), initial);
#endif
#if defined(__ADX__)
    return fastcsum_nofold_adx_v2(b.data(), b.size(), initial);
#elif defined(__x86_64__)
    return fastcsum_nofold_x64_64b(b.data(), b.size(), initial);
#else
    return fastcsum_nofold_generic64(b.data(), b.size(), initial);
#endif
}

template <size_t E1, size_t E2>
static inline uint64_t pseudo_header_checksum_nofold(
    uint8_t proto,
    std::span<const uint8_t, E1> srcAddr,
    std::span<const uint8_t, E2> dstAddr,
    uint16_t l4Len) {
    static_assert(E1 > 1 && E2 > 1);
    auto sum = checksum_impl::checksum_nofold(srcAddr, 0);
    sum = checksum_impl::checksum_nofold(dstAddr, sum);
    std::array<uint8_t, 4> proto_bytes;
    boost::endian::store_big_u16(&proto_bytes[0], proto);
    boost::endian::store_big_u16(&proto_bytes[2], l4Len);
    sum = checksum_impl::checksum_nofold(std::span<const uint8_t, 4>(proto_bytes), sum);
    return sum;
}

} // namespace checksum_impl

template <size_t E1, size_t E2>
static inline uint16_t pseudo_header_checksum(
    uint8_t proto,
    std::span<const uint8_t, E1> srcAddr,
    std::span<const uint8_t, E2> dstAddr,
    uint16_t l4Len) {
    auto ac = checksum_impl::pseudo_header_checksum_nofold(proto, srcAddr, dstAddr, l4Len);
    return fastcsum_fold_complement(ac);
}

template <typename TAddress>
static inline uint16_t pseudo_header_checksum(
    uint8_t proto,
    const TAddress &srcAddr,
    const TAddress &dstAddr,
    uint16_t l4Len) {
    std::span<const uint8_t, sizeof(TAddress)> srcAddrBytes(
        reinterpret_cast<const uint8_t *>(&srcAddr),
        sizeof(srcAddr));
    std::span<const uint8_t, sizeof(TAddress)> dstAddrBytes(
        reinterpret_cast<const uint8_t *>(&dstAddr),
        sizeof(dstAddr));
    auto ac = checksum_impl::pseudo_header_checksum_nofold(proto, srcAddrBytes, dstAddrBytes, l4Len);
    return fastcsum_fold_complement(ac);
}

static inline uint16_t checksum(std::span<const uint8_t> b, uint64_t initial) {
    auto ac = checksum_impl::checksum_nofold(b, initial);
    return fastcsum_fold_complement(ac);
}

uint16_t calc_l4_checksum(std::span<const uint8_t> thispkt, bool isv6, bool istcp, uint16_t csum_start);

} // namespace wireglider
