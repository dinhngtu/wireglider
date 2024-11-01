#pragma once

#include <utility>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <fmt/format.h>
#include <boost/endian.hpp>
#include <tdutil/function_traits.hpp>
#include <tdutil/util.hpp>

#include "dbgprint.hpp"
#include "worker/flowkey.hpp"
#include "checksum.hpp"
#include "worker/offload.hpp"

namespace wireglider::worker_impl {

template <auto F>
using ip_header_of_t = std::remove_pointer_t<typename tdutil::result_type_t<decltype(F)>::first_type>;
template <auto F>
using address_type_of_t = typename std::remove_cvref_t<tdutil::first_argument_t<decltype(F)>>::address_type;

std::pair<const struct ip *, uint8_t> fill_fk_ip4(
    FlowKey<in_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags);

std::pair<const ip6_hdr *, uint8_t> fill_fk_ip6(
    FlowKey<in6_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags);

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
    auto iphsize = flags.vnethdr.csum_start;
    if (ippkt.size() - iphsize <= sizeof(tcphdr))
        // exclude empty packets as well
        return nullptr;
    if (calc_l4_checksum(ippkt, flags.isv6(), true, iphsize)) {
        DBG_PRINT("tcp checksum drop\n");
        return nullptr;
    }
    auto tcp = reinterpret_cast<const tcphdr *>(&ippkt[iphsize]);
    auto thlen = 4u * tcp->doff;
    if (thlen < sizeof(tcphdr) || ippkt.size() - iphsize <= thlen)
        return nullptr;
    if (tcp->fin || tcp->syn || tcp->rst || tcp->urg || tcp->res2)
        return nullptr;
    flags.istcp() = true;
    flags.ispsh() = !!tcp->psh;
    flags.vnethdr.gso_type = flags.isv6() ? VIRTIO_NET_HDR_GSO_TCPV6 : VIRTIO_NET_HDR_GSO_TCPV4;
    if (IPTOS_ECN(fk.tos) == IPTOS_ECN_CE)
        flags.vnethdr.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
    flags.vnethdr.hdr_len += thlen;
    flags.vnethdr.csum_offset = offsetof(tcphdr, check);
    fk.srcport = boost::endian::big_to_native(tcp->source);
    fk.dstport = boost::endian::big_to_native(tcp->dest);
    fk.tcpack = boost::endian::big_to_native(tcp->ack_seq);
    fk.seq = boost::endian::big_to_native(tcp->seq);
    return tcp;
}

template <typename T>
static const udphdr *fill_fk_udp(FlowKey<T> &fk, std::span<const uint8_t> ippkt, PacketFlags &flags) {
    auto iphsize = flags.vnethdr.csum_start;
    if (ippkt.size() - iphsize <= sizeof(udphdr))
        return nullptr;
    if (calc_l4_checksum(ippkt, flags.isv6(), false, iphsize)) {
        DBG_PRINT("udp checksum drop\n");
        return nullptr;
    }
    auto udp = reinterpret_cast<const udphdr *>(&ippkt[iphsize]);
    flags.istcp() = false;
    flags.ispsh() = false;
    flags.vnethdr.gso_type = WIREGLIDER_VIRTIO_NET_HDR_GSO_UDP_L4;
    flags.vnethdr.hdr_len += sizeof(udphdr);
    flags.vnethdr.csum_offset = offsetof(udphdr, check);
    fk.srcport = boost::endian::big_to_native(udp->source);
    fk.dstport = boost::endian::big_to_native(udp->dest);
    fk.tcpack = 0;
    // position the packet last in its own flow
    fk.seq = UINT32_MAX;
    return udp;
}

template <auto fill_ip>
static DecapOutcome evaluate_packet(
    std::span<const uint8_t> ippkt,
    FlowKey<address_type_of_t<fill_ip>> &fk,
    PacketFlags &flags,
    uint8_t ecn_outer,
    bool has_uso) {
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
        if (!has_uso || !fill_fk_udp(fk, ippkt, flags))
            return GRO_NOADD;
        break;
    }
    default:
        return GRO_NOADD;
    }

    flags.vnethdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    flags.vnethdr.gso_size = fk.segment_size = ippkt.size() - flags.vnethdr.hdr_len;

    return GRO_ADD;
}

// returns true if the next flow was merged and erased
template <typename T, template <typename> typename FlowMap>
static bool merge_next_flow(FlowMap<T> &flow, const typename FlowMap<T>::iterator &it) {
    if (it == flow.begin())
        return false;
    if (it->second->flags.ispsh() || it->second->flags.issealed())
        return false;
    auto next = it - 1;
    if (!it->second->is_mergeable(*next->second))
        return false;
    if (it->second->flags.istcp() ? !it->first.matches_tcp(next->first, it->second->size_bytes())
                                  : !it->first.matches_udp(next->first))
        return false;
    it->second->extend(*next->second);
    flow.erase(next);
    return true;
}

// returns true if this flow was merged with the previous flow and erased
template <typename T, template <typename> typename FlowMap>
static bool merge_prev_flow(FlowMap<T> &flow, const typename FlowMap<T>::iterator &it) {
    auto prev = it + 1;
    if (prev == flow.end())
        return false;
    if (prev->second->flags.ispsh() || prev->second->flags.issealed())
        return false;
    if (!prev->second->is_mergeable(*it->second))
        return false;
    if (it->second->flags.istcp() ? !prev->first.matches_tcp(it->first, prev->second->size_bytes())
                                  : !prev->first.matches_udp(it->first))
        return false;
    prev->second->extend(*it->second);
    flow.erase(it);
    return true;
}

template <typename T, template <typename> typename FlowMap>
struct FlowMapTraits {};

template <typename T, template <typename> typename FlowMap>
static void append_flow(
    FlowMap<T> &flow,
    FlowKey<T> &fk,
    std::span<const uint8_t> pkthdr,
    std::span<const uint8_t> pktdata,
    PacketFlags &flags,
    uint32_t &udpid) {
    auto [it, usable] = find_flow<T, FlowMap>(flow, fk, pktdata, flags);
    bool created;
    if (!usable) {
        // create a new flow
        if (!flags.istcp())
            fk.seq = udpid++;
        std::tie(it, created) =
            flow.emplace(fk, FlowMapTraits<T, FlowMap>::create_batch(pkthdr, fk.segment_size, flags));
        assert(created);
    }
    it->second->append(pktdata);
    if (pktdata.size() != fk.segment_size)
        it->second->flags.issealed() = true;
    if (it->second->flags.isv6()) {
        auto ip6 = it->second->ip6hdr();
        boost::endian::big_to_native_inplace(ip6->ip6_flow);
        ip6->ip6_flow &= ~0xFF00000;
        ip6->ip6_flow |= static_cast<uint32_t>(fk.tos) << 20;
        boost::endian::native_to_big_inplace(ip6->ip6_flow);
    } else {
        it->second->ip4hdr()->ip_tos = fk.tos;
    }
    if (flags.istcp() && flags.ispsh()) {
        it->second->tcphdr()->psh |= 1;
        it->second->flags.ispsh() = true;
    }

    if (merge_next_flow<T, FlowMap>(flow, it))
        return;
    if (merge_prev_flow<T, FlowMap>(flow, it))
        return;
}

} // namespace wireglider::worker_impl
