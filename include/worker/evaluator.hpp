#pragma once

#include <utility>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <tdutil/function_traits.hpp>
#include <tdutil/util.hpp>

#include "worker/flowkey.hpp"
#include "checksum.hpp"

namespace wireglider::worker_impl {

static std::pair<const struct ip *, uint8_t> fill_fk_ip4(
    FlowKey<in_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags) {
    auto ip = tdutil::start_lifetime_as<struct ip>(ippkt.data());
    // no support for long ipv4 headers yet
    if (ip->ip_hl * 4u != sizeof(struct ip))
        return {nullptr, IPPROTO_RAW};
    if (ippkt.size() != boost::endian::big_to_native(ip->ip_len))
        return {nullptr, IPPROTO_RAW};
    // no fragmenting of any kind
    if (boost::endian::big_to_native(ip->ip_off))
        return {nullptr, IPPROTO_RAW};
    // iph checksum
    if (checksum(ippkt.subspan(0, sizeof(struct ip)), 0))
        return {nullptr, IPPROTO_RAW};
    flags.vnethdr.hdr_len = flags.vnethdr.csum_start = sizeof(struct ip);
    flags.isv6() = false;
    fk.srcip = ip->ip_src;
    fk.dstip = ip->ip_dst;
    fk.tos = ip->ip_tos;
    fk.ttl = ip->ip_ttl;
    return std::make_pair(ip, ip->ip_p);
}

static std::pair<const ip6_hdr *, uint8_t> fill_fk_ip6(
    FlowKey<in6_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags) {
    auto ip = tdutil::start_lifetime_as<ip6_hdr>(ippkt.data());
    auto rest = ippkt.subspan(sizeof(ip6_hdr));
    if (rest.size() != boost::endian::big_to_native(ip->ip6_plen))
        return {nullptr, IPPROTO_RAW};
    flags.isv6() = true;
    flags.vnethdr.hdr_len = flags.vnethdr.csum_start = sizeof(ip6_hdr);
    fk.srcip = ip->ip6_src;
    fk.dstip = ip->ip6_dst;
    fk.tos = (boost::endian::big_to_native(ip->ip6_flow) >> 20) & 0xff;
    fk.ttl = ip->ip6_hlim;
    return std::make_pair(ip, ip->ip6_nxt);
}

template <auto F>
using ip_header_of_t = std::remove_pointer_t<typename tdutil::result_type_t<decltype(F)>::first_type>;
template <auto F>
using address_type_of_t = typename std::remove_cvref_t<tdutil::first_argument_t<decltype(F)>>::address_type;

template <typename T>
static bool fill_fk_ecn(FlowKey<T> &fk, uint8_t ecn_outer) {
    // RFC 6040 section 4.2
    // ecnmap consists of groups of 4 bits indexed by inner (2 bits)||outer (2 bits) (see fig 4)
    // each group is warn (2 bits)||resulting ecn (2 bits)
    // warn 1 = (!), warn 2 = (!!!), warn 3 = drop
    const uint64_t ecnmap = 0x3B3331223151F880;
    uint8_t ecn_inner = IPTOS_ECN(fk.tos);
    auto newecn = ecnmap >> (((ecn_inner << 2) | ecn_outer) * 4);
    switch ((newecn >> 2) & 3) {
    case 0:
        break;
    case 1:
    case 2:
        // might want to warn here
        break;
    case 3:
        return false;
    }
    fk.tos = IPTOS_DSCP(fk.tos) | IPTOS_ECN(newecn);
    return true;
}

template <typename T>
static const tcphdr *fill_fk_tcp(FlowKey<T> &fk, std::span<const uint8_t> ippkt, PacketFlags &flags) {
    auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
    if (ippkt.size() - iphsize <= sizeof(tcphdr))
        // exclude empty packets as well
        return nullptr;
    if (calc_l4_checksum(ippkt, flags.isv6(), true, iphsize))
        return nullptr;
    auto tcp = tdutil::start_lifetime_as<tcphdr>(&ippkt[iphsize]);
    if (tcp->doff != 5)
        return nullptr;
    if (tcp->fin || tcp->syn || tcp->rst || tcp->urg || tcp->res2)
        return nullptr;
    flags.istcp() = true;
    flags.ispsh() = !!tcp->psh;
    flags.vnethdr.hdr_len += sizeof(tcphdr);
    flags.vnethdr.csum_offset = offsetof(tcphdr, check);
    fk.srcport = boost::endian::big_to_native(tcp->source);
    fk.dstport = boost::endian::big_to_native(tcp->dest);
    fk.tcpack = boost::endian::big_to_native(tcp->ack_seq);
    fk.seq = boost::endian::big_to_native(tcp->seq);
    return tcp;
}

template <typename T>
static const udphdr *fill_fk_udp(FlowKey<T> &fk, std::span<const uint8_t> ippkt, PacketFlags &flags) {
    auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
    if (ippkt.size() - iphsize < sizeof(tcphdr))
        return nullptr;
    if (calc_l4_checksum(ippkt, flags.isv6(), false, iphsize))
        return nullptr;
    auto udp = tdutil::start_lifetime_as<udphdr>(&ippkt[iphsize]);
    flags.istcp() = false;
    flags.ispsh() = false;
    flags.vnethdr.hdr_len += sizeof(udphdr);
    flags.vnethdr.csum_offset = offsetof(udphdr, check);
    fk.srcport = boost::endian::big_to_native(udp->source);
    fk.dstport = boost::endian::big_to_native(udp->dest);
    fk.tcpack = 0;
    fk.seq = UINT32_MAX;
    return udp;
}

template <auto fill_ip>
static DecapOutcome evaluate_packet(
    std::span<const uint8_t> ippkt,
    FlowKey<address_type_of_t<fill_ip>> &fk,
    PacketFlags &flags,
    uint8_t ecn_outer) {
    if (ippkt.size() < sizeof(ip_header_of_t<fill_ip>))
        return GRO_NOADD;
    else if (ippkt.size() > UINT16_MAX)
        return GRO_NOADD;

    auto [ip, proto] = fill_ip(fk, ippkt, flags);
    if (!ip)
        return GRO_NOADD;

    if (!fill_fk_ecn(fk, ecn_outer))
        return GRO_DROP;

    switch (proto) {
    case IPPROTO_TCP: {
        if (!fill_fk_tcp(fk, ippkt, flags))
            return GRO_NOADD;
        break;
    }
    case IPPROTO_UDP: {
        if (!fill_fk_udp(fk, ippkt, flags))
            return GRO_NOADD;
        break;
    }
    default:
        return GRO_NOADD;
    }
    fk.segment_size = ippkt.size() - sizeof(*ip) - (flags.istcp() ? sizeof(tcphdr) : sizeof(udphdr));

    return GRO_ADD;
}

} // namespace wireglider::worker_impl
