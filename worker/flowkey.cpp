#include <utility>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <tdutil/function_traits.hpp>

#include "worker.hpp"
#include "checksum.hpp"

using namespace boost::endian;
using namespace wgss::worker_impl;
using enum DecapBatch::Outcome;

namespace wgss::worker_impl {

template <typename T>
static std::pair<typename FlowMap<T>::iterator, bool> find_flow(
    FlowMap<T> &flow,
    const FlowKey<T> &fk,
    std::span<const uint8_t> pktdata,
    const PacketFlags &flags) {
    auto it = flow.lower_bound(fk);
    if (it == flow.end())
        return {it, false};
    if (!it->second.is_appendable(pktdata.size()))
        return {it, false};
    if (flags.istcp() ? !it->first.is_consecutive_with(fk, 1, pktdata.size()) : !it->first.matches(fk))
        return {it, false};
    if (flags.istcp() && it->second.flags.ispsh())
        return {it, false};
    return {it, true};
}

// returns true if the next flow was merged and erased
template <typename T>
static bool merge_next_flow(FlowMap<T> &flow, const typename FlowMap<T>::iterator &it) {
    if (it == flow.begin())
        return false;
    if (it->second.flags.ispsh())
        return false;
    auto next = it - 1;
    if (!it->second.is_mergeable(next->second))
        return false;
    if (it->second.flags.istcp() ? !it->first.is_consecutive_with(next->first, it->second.count, it->second.buf.size())
                                 : !it->first.matches(next->first))
        return false;
    it->second.extend(next->second);
    flow.erase(next);
    return true;
}

// returns true if this flow was merged with the previous flow and erased
template <typename T>
static bool merge_prev_flow(FlowMap<T> &flow, const typename FlowMap<T>::iterator &it) {
    auto prev = it + 1;
    if (prev == flow.end())
        return false;
    if (!prev->second.is_mergeable(it->second))
        return false;
    if (it->second.flags.istcp()
            ? !prev->first.is_consecutive_with(it->first, prev->second.count, prev->second.buf.size())
            : !prev->first.matches(it->first))
        return false;
    if (prev->second.flags.ispsh())
        return false;
    prev->second.extend(it->second);
    flow.erase(it);
    return true;
}

template <typename T>
static void append_flow(
    FlowMap<T> &flow,
    FlowKey<T> &fk,
    std::span<const uint8_t> pkthdr,
    std::span<const uint8_t> pktdata,
    PacketFlags &flags) {
    auto [it, usable] = find_flow(flow, fk, pktdata, flags);
    bool created;
    if (!usable) {
        // create a new flow
        if (!flags.istcp())
            // udp: continue from last flow
            fk.seq = (it != flow.end()) ? (it->first.seq + 1) : 0;
        flags.vnethdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        if (flags.istcp())
            flags.vnethdr.gso_type = flags.isv6() ? VIRTIO_NET_HDR_GSO_TCPV6 : VIRTIO_NET_HDR_GSO_TCPV4;
        else
            flags.vnethdr.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
        std::tie(it, created) = flow.emplace(fk, OwnedPacketBatch(pkthdr, size_t(4) * fk.segment_size, flags));
        assert(created);
    }
    it->second.append(pktdata);
    if (flags.istcp() && flags.ispsh()) {
        it->second.tcphdr()->psh |= 1;
        it->second.flags.ispsh() = true;
    }

    /*
     * There are only two possibilities:
     * - Appending to an existing flow, bridging a gap (flow1-newdata->flow2)
     * - Creating a new flow, bridging with next flow (newdata->flow)
     * with `-` being a simple flow append and `->` being a flow merge.
     * IOW, merge_next_flow and merge_prev_flow can't happen at the same time.
     * Therefore there's no need to worry about iterator invalidation.
     */
    [[maybe_unused]] bool next_merged = merge_next_flow(flow, it);
    [[maybe_unused]] bool prev_merged = merge_prev_flow(flow, it);
    assert(!(next_merged && prev_merged));
}

static std::pair<const struct ip *, uint8_t> fill_fk_ip4(
    FlowKey<in_addr> &fk,
    std::span<const uint8_t> ippkt,
    PacketFlags &flags) {
    auto ip = reinterpret_cast<const struct ip *>(ippkt.data());
    // no support for long ipv4 headers yet
    if (ip->ip_hl * 4u != sizeof(struct ip))
        return {nullptr, IPPROTO_RAW};
    if (ippkt.size() != big_to_native(ip->ip_len))
        return {nullptr, IPPROTO_RAW};
    // no fragmenting of any kind
    if (big_to_native(ip->ip_off))
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
    auto ip = reinterpret_cast<const ip6_hdr *>(ippkt.data());
    auto rest = ippkt.subspan(sizeof(ip6_hdr));
    if (rest.size() != big_to_native(ip->ip6_ctlun.ip6_un1.ip6_un1_plen))
        return {nullptr, IPPROTO_RAW};
    flags.isv6() = true;
    flags.vnethdr.hdr_len = flags.vnethdr.csum_start = sizeof(ip6_hdr);
    fk.srcip = ip->ip6_src;
    fk.dstip = ip->ip6_dst;
    fk.tos = (big_to_native(ip->ip6_flow) >> 20) & 0xff;
    fk.ttl = ip->ip6_hlim;
    return std::make_pair(ip, ip->ip6_ctlun.ip6_un1.ip6_un1_nxt);
}

template <auto F>
using ip_header_of_t = std::remove_pointer_t<typename tdutil::result_type_t<decltype(F)>::first_type>;
template <auto F>
using address_type_of_t = std::remove_cvref_t<tdutil::first_argument_t<decltype(F)>>::address_type;

template <typename T>
static const tcphdr *fill_fk_tcp(FlowKey<T> &fk, std::span<const uint8_t> ippkt, PacketFlags &flags) {
    auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
    if (ippkt.size() - iphsize <= sizeof(tcphdr))
        // exclude empty packets as well
        return nullptr;
    if (calc_l4_checksum(ippkt, flags.isv6(), true, iphsize))
        return nullptr;
    auto tcp = reinterpret_cast<const tcphdr *>(&ippkt[iphsize]);
    if (tcp->doff != 5)
        return nullptr;
    if (tcp->fin || tcp->syn || tcp->rst || tcp->urg || tcp->res2)
        return nullptr;
    flags.istcp() = true;
    flags.ispsh() = !!tcp->psh;
    flags.vnethdr.hdr_len += sizeof(tcphdr);
    flags.vnethdr.csum_offset = offsetof(tcphdr, check);
    fk.srcport = big_to_native(tcp->source);
    fk.dstport = big_to_native(tcp->dest);
    fk.tcpack = big_to_native(tcp->ack_seq);
    fk.seq = big_to_native(tcp->seq);
    return tcp;
}

template <typename T>
static const udphdr *fill_fk_udp(FlowKey<T> &fk, std::span<const uint8_t> ippkt, PacketFlags &flags) {
    auto iphsize = flags.isv6() ? sizeof(ip6_hdr) : sizeof(struct ip);
    if (ippkt.size() - iphsize < sizeof(tcphdr))
        return nullptr;
    if (calc_l4_checksum(ippkt, flags.isv6(), false, iphsize))
        return nullptr;
    auto udp = reinterpret_cast<const udphdr *>(&ippkt[iphsize]);
    flags.istcp() = false;
    flags.ispsh() = false;
    flags.vnethdr.hdr_len += sizeof(udphdr);
    flags.vnethdr.csum_offset = offsetof(udphdr, check);
    fk.srcport = big_to_native(udp->source);
    fk.dstport = big_to_native(udp->dest);
    fk.tcpack = 0;
    fk.seq = UINT32_MAX;
    return udp;
}

template <auto fill_ip>
static DecapBatch::Outcome evaluate_packet(
    std::span<const uint8_t> ippkt,
    FlowKey<address_type_of_t<fill_ip>> &fk,
    PacketFlags &flags) {
    if (ippkt.size() < sizeof(ip_header_of_t<fill_ip>))
        return GRO_NOADD;
    else if (ippkt.size() > UINT16_MAX)
        return GRO_NOADD;

    auto [ip, proto] = fill_ip(fk, ippkt, flags);
    if (!ip)
        return GRO_NOADD;

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

template <auto fill_ip>
static DecapBatch::Outcome do_push_packet(
    std::span<const uint8_t> ippkt,
    FlowMap<address_type_of_t<fill_ip>> &tcpflow,
    FlowMap<address_type_of_t<fill_ip>> &udpflow,
    std::deque<std::vector<uint8_t>> &unrel) {
    FlowKey<address_type_of_t<fill_ip>> fk{};
    PacketFlags flags;
    auto res = evaluate_packet<fill_ip>(ippkt, fk, flags);
    switch (res) {
    case GRO_ADD: {
        auto pkthdr = ippkt.subspan(0, flags.vnethdr.hdr_len);
        auto pktdata = ippkt.subspan(flags.vnethdr.hdr_len);
        append_flow(flags.istcp() ? tcpflow : udpflow, fk, pkthdr, pktdata, flags);
        break;
    }
    case GRO_NOADD:
        unrel.emplace_back(ippkt.begin(), ippkt.end());
        break;
    case GRO_DROP:
        break;
    }
    return res;
}

DecapBatch::Outcome DecapBatch::push_packet_v4(std::span<const uint8_t> ippkt) {
    return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel);
}

DecapBatch::Outcome DecapBatch::push_packet_v6(std::span<const uint8_t> ippkt) {
    return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel);
}

DecapBatch::Outcome DecapBatch::push_packet(std::span<const uint8_t> ippkt) {
    if (ippkt.size() < sizeof(struct ip))
        return GRO_NOADD;
    auto ip = reinterpret_cast<const struct ip *>(ippkt.data());
    if (ip->ip_v == 4)
        return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel);
    else
        return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel);
}

void DecapBatch::aggregate_udp() {
}

} // namespace wgss::worker_impl