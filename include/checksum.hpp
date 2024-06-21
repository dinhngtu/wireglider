#pragma once

// useful references:
// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/checksum.go
// https://blogs.igalia.com/dpino/2018/06/14/fast-checksum-computation
// https://github.com/snabbco/snabb/commit/0068df61213d030ac6064f0d5db8705373e7e3c7

#include <cstdint>
#include <span>
#include <array>
#include <boost/endian.hpp>

#include <fastcsum.hpp>

namespace wgss {

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
    bool c1 = __builtin_add_overflow(ret, *reinterpret_cast<const uint64_t *>(&b[0]), &ret);
    ret += c1;
    bool c2 = __builtin_add_overflow(ret, *reinterpret_cast<const uint64_t *>(&b[8]), &ret);
    return ret + c2;
}

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, 8> b, uint64_t initial) {
    uint64_t ret = initial;
    bool c = __builtin_add_overflow(ret, *reinterpret_cast<const uint64_t *>(&b[0]), &ret);
    return ret + c;
}

template <>
uint64_t checksum_nofold(std::span<const uint8_t, 4> b, uint64_t initial) {
    uint64_t ret = initial;
    bool c = __builtin_add_overflow(ret, static_cast<uint64_t>(*reinterpret_cast<const uint32_t *>(&b[0])), &ret);
    return ret + c;
}

inline uint64_t checksum_nofold(std::span<const uint8_t, 2> b, uint64_t initial) {
    uint64_t ret = initial;
    bool c = __builtin_add_overflow(ret, static_cast<uint64_t>(*reinterpret_cast<const uint16_t *>(&b[0])), &ret);
    return ret + c;
}

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, 1> b, uint64_t initial) {
    uint64_t ret = initial;
    bool c = __builtin_add_overflow(ret, static_cast<uint64_t>(b[0]), &ret);
    return ret + c;
}

template <>
inline uint64_t checksum_nofold(std::span<const uint8_t, std::dynamic_extent> b, uint64_t initial) {
    // TODO: detect fastcsum compiled features
#if defined(__AVX2__)
    return fastcsum::fastcsum_nofold_avx2_v3(b.data(), b.size(), initial);
#elif defined(__AVX__) || defined(__SSE4_1__)
    return fastcsum::fastcsum_nofold_vec128(b.data(), b.size(), initial);
#elif defined(__ADX__)
    return fastcsum::fastcsum_nofold_adx_v2(b.data(), b.size(), initial);
#elif defined(__x86_64__)
    return fastcsum::fastcsum_nofold_x64_64b(b.data(), b.size(), initial);
#else
    return fastcsum::fastcsum_nofold_generic64(b.data(), b.size(), initial);
#endif
}

template <size_t E1, size_t E2>
static inline uint64_t pseudo_header_checksum_nofold(
    uint8_t proto,
    std::span<const uint8_t, E1> srcAddr,
    std::span<const uint8_t, E2> dstAddr,
    uint16_t totalLen) {
    auto sum = checksum_impl::checksum_nofold(srcAddr, 0);
    sum = checksum_impl::checksum_nofold(dstAddr, sum);
    std::array<uint16_t, 2> proto_bytes = {
        boost::endian::native_to_big(static_cast<uint16_t>(proto)),
        boost::endian::native_to_big(totalLen)};
    sum = checksum_impl::checksum_nofold(
        std::span<const uint8_t, 4>(reinterpret_cast<const uint8_t *>(proto_bytes.data()), 4),
        sum);
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
    return fastcsum::fold_complement_checksum64(ac);
}

static inline uint16_t checksum(std::span<const uint8_t> b, uint64_t initial) {
    auto ac = checksum_impl::checksum_nofold(b, initial);
    return fastcsum::fold_complement_checksum64(ac);
}

} // namespace wgss
