// API adapted from
// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/tun/checksum.go
// implementation adapted from https://blogs.igalia.com/dpino/2018/06/14/fast-checksum-computation
//                             https://github.com/snabbco/snabb/commit/0068df61213d030ac6064f0d5db8705373e7e3c7

#include "checksum.hpp"

namespace wgss {

namespace checksum_impl {

uint64_t checksum_nofold_generic(std::span<const uint8_t, std::dynamic_extent> b, uint64_t initial) {
    uint64_t ac = initial;
    uint64_t carry = 0;

    while (b.size() >= 32) {
        ac = addc(ac, *reinterpret_cast<const uint64_t *>(&b[0]), 0, &carry);
        ac = addc(ac, *reinterpret_cast<const uint64_t *>(&b[8]), carry, &carry);
        ac = addc(ac, *reinterpret_cast<const uint64_t *>(&b[16]), carry, &carry);
        ac = addc(ac, *reinterpret_cast<const uint64_t *>(&b[24]), carry, &carry);
        ac += carry;
        b = b.subspan(32);
    }
    if (b.size() >= 16) {
        ac = addc(ac, *reinterpret_cast<const uint64_t *>(&b[0]), 0, &carry);
        ac = addc(ac, *reinterpret_cast<const uint64_t *>(&b[8]), carry, &carry);
        ac += carry;
        b = b.subspan(16);
    }
    if (b.size() >= 8) {
        ac = addc(ac, *reinterpret_cast<const uint64_t *>(&b[0]), 0, &carry);
        ac += carry;
        b = b.subspan(8);
    }
    if (b.size() >= 4) {
        ac = addc(ac, static_cast<uint64_t>(*reinterpret_cast<const uint32_t *>(&b[0])), 0, &carry);
        ac += carry;
        b = b.subspan(4);
    }
    if (b.size() >= 2) {
        ac = addc(ac, static_cast<uint64_t>(*reinterpret_cast<const uint16_t *>(&b[0])), 0, &carry);
        ac += carry;
        b = b.subspan(2);
    }
    if (b.size()) {
        ac = addc(ac, static_cast<uint64_t>(b[0]), 0, &carry);
        ac += carry;
    }

    return ac;
}

} // namespace checksum_impl

} // namespace wgss
