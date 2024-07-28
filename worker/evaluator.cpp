
#include <cstdint>
#include <span>
#include <utility>
#include <netinet/in.h>
#include <fmt/format.h>

#include "checksum.hpp"
#include "dbgprint.hpp"
#include "worker/flowkey.hpp"

namespace wireglider::worker_impl {

std::pair<const struct ip *, uint8_t> fill_fk_ip4(
    FlowKey<in_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags) {
    auto ip = reinterpret_cast<const struct ip *>(ippkt.data());
    // no support for long ipv4 headers yet
    if (ip->ip_hl * 4u != sizeof(struct ip))
        return {nullptr, IPPROTO_RAW};
    if (ippkt.size() != boost::endian::big_to_native(ip->ip_len))
        return {nullptr, IPPROTO_RAW};
    // no fragmenting of any kind
    if (boost::endian::big_to_native(ip->ip_off) & ~IP_DF)
        return {nullptr, IPPROTO_RAW};
    // iph checksum
    if (checksum(ippkt.subspan(0, sizeof(struct ip)), 0)) {
        DBG_PRINT("ip checksum drop\n");
        return {nullptr, IPPROTO_RAW};
    }
    flags.vnethdr.hdr_len = flags.vnethdr.csum_start = sizeof(struct ip);
    flags.isv6() = false;
    fk.srcip = ip->ip_src;
    fk.dstip = ip->ip_dst;
    fk.frag = ip->ip_off;
    fk.tos = ip->ip_tos;
    fk.ttl = ip->ip_ttl;
    return std::make_pair(ip, ip->ip_p);
}

std::pair<const ip6_hdr *, uint8_t> fill_fk_ip6(
    FlowKey<in6_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags) {
    auto ip = reinterpret_cast<const ip6_hdr *>(ippkt.data());
    auto rest = ippkt.subspan(sizeof(ip6_hdr));
    if (rest.size() != boost::endian::big_to_native(ip->ip6_plen))
        return {nullptr, IPPROTO_RAW};
    flags.isv6() = true;
    flags.vnethdr.hdr_len = flags.vnethdr.csum_start = sizeof(ip6_hdr);
    fk.srcip = ip->ip6_src;
    fk.dstip = ip->ip6_dst;
    fk.frag = 0;
    fk.tos = (boost::endian::big_to_native(ip->ip6_flow) >> 20) & 0xff;
    fk.ttl = ip->ip6_hlim;
    return std::make_pair(ip, ip->ip6_nxt);
}

} // namespace wireglider::worker_impl
