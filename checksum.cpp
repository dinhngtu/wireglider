#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "checksum.hpp"

namespace wireglider {

uint16_t calc_l4_checksum(std::span<const uint8_t> ippkt, bool isv6, bool istcp, uint16_t csum_start) {
    uint64_t l4_csum_tmp;
    if (isv6) {
        const auto addroff = offsetof(ip6_hdr, ip6_src);
        const auto addrsize = sizeof(in6_addr);
        std::span<const uint8_t, addrsize> srcaddr = ippkt.subspan<addroff, addrsize>();
        std::span<const uint8_t, addrsize> dstaddr = ippkt.subspan<addroff + addrsize, addrsize>();
        l4_csum_tmp = checksum_impl::pseudo_header_checksum_nofold(
            istcp ? IPPROTO_TCP : IPPROTO_UDP,
            srcaddr,
            dstaddr,
            ippkt.size() - csum_start);
    } else {
        const auto addroff = offsetof(struct ip, ip_src);
        const auto addrsize = sizeof(in_addr);
        std::span<const uint8_t, addrsize> srcaddr = ippkt.subspan<addroff, addrsize>();
        std::span<const uint8_t, addrsize> dstaddr = ippkt.subspan<addroff + addrsize, addrsize>();
        l4_csum_tmp = checksum_impl::pseudo_header_checksum_nofold(
            istcp ? IPPROTO_TCP : IPPROTO_UDP,
            srcaddr,
            dstaddr,
            ippkt.size() - csum_start);
    }
    return checksum(ippkt.subspan(csum_start), l4_csum_tmp);
}

} // namespace wireglider
