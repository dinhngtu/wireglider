#include <utility>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <tdutil/util.hpp>

#include "worker.hpp"
#include "worker/evaluator.hpp"

using namespace boost::endian;
using namespace wireglider::worker_impl;
using enum DecapOutcome;

namespace wireglider::worker_impl {

template <typename T>
static std::pair<typename RefFlowMap<T>::iterator, bool> find_flow(
    RefFlowMap<T> &flow,
    const FlowKey<T> &fk,
    std::span<const uint8_t> pktdata,
    const PacketFlags &flags) {
    auto it = flow.lower_bound(fk);
    if (it == flow.end())
        return {it, false};
    if (!it->second->is_appendable(pktdata.size()))
        return {it, false};
    if (flags.istcp() ? !it->first.is_consecutive_with(fk, pktdata.size()) : !it->first.matches(fk))
        return {it, false};
    if (flags.istcp() && it->second->flags.ispsh())
        return {it, false};
    return {it, true};
}

// returns true if the next flow was merged and erased
template <typename T>
static bool merge_next_flow(RefFlowMap<T> &flow, const typename RefFlowMap<T>::iterator &it) {
    if (it == flow.begin())
        return false;
    if (it->second->flags.ispsh())
        return false;
    auto next = it - 1;
    if (!it->second->is_mergeable(*next->second))
        return false;
    if (it->second->flags.istcp() ? !it->first.is_consecutive_with(next->first, it->second->bytes)
                                  : !it->first.matches(next->first))
        return false;
    it->second->extend(*next->second);
    flow.erase(next);
    return true;
}

// returns true if this flow was merged with the previous flow and erased
template <typename T>
static bool merge_prev_flow(RefFlowMap<T> &flow, const typename RefFlowMap<T>::iterator &it) {
    auto prev = it + 1;
    if (prev == flow.end())
        return false;
    if (!prev->second->is_mergeable(*it->second))
        return false;
    if (it->second->flags.istcp() ? !prev->first.is_consecutive_with(it->first, prev->second->bytes)
                                  : !prev->first.matches(it->first))
        return false;
    if (prev->second->flags.ispsh())
        return false;
    prev->second->extend(*it->second);
    flow.erase(it);
    return true;
}

template <typename T>
static void append_flow(
    RefFlowMap<T> &flow,
    FlowKey<T> &fk,
    std::span<const uint8_t> pkthdr,
    std::span<const uint8_t> pktdata,
    PacketFlags &flags,
    uint32_t &udpid) {
    auto [it, usable] = find_flow(flow, fk, pktdata, flags);
    bool created;
    if (!usable) {
        // create a new flow
        if (!flags.istcp())
            fk.seq = udpid++;
        flags.vnethdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        if (flags.istcp()) {
            flags.vnethdr.gso_type = flags.isv6() ? VIRTIO_NET_HDR_GSO_TCPV6 : VIRTIO_NET_HDR_GSO_TCPV4;
            if (IPTOS_ECN(fk.tos) == IPTOS_ECN_CE)
                flags.vnethdr.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
        } else {
            flags.vnethdr.gso_type = VIRTIO_NET_HDR_GSO_UDP_L4;
        }
        std::tie(it, created) = flow.emplace(fk, std::make_unique<PacketRefBatch>(pkthdr, flags));
        assert(created);
    }
    it->second->append(pktdata);
    if (it->second->flags.isv6()) {
        auto ip6 = it->second->ip6hdr();
        big_to_native_inplace(ip6->ip6_flow);
        ip6->ip6_flow &= ~0xFF00000;
        ip6->ip6_flow |= static_cast<uint32_t>(fk.tos) << 20;
        native_to_big_inplace(ip6->ip6_flow);
    } else {
        it->second->ip4hdr()->ip_tos = fk.tos;
    }
    if (flags.istcp() && flags.ispsh()) {
        it->second->tcphdr()->psh |= 1;
        it->second->flags.ispsh() = true;
    }

    if (merge_next_flow(flow, it))
        return;
    if (merge_prev_flow(flow, it))
        return;
}

template <auto fill_ip>
static DecapOutcome do_push_packet(
    std::span<const uint8_t> ippkt,
    RefFlowMap<address_type_of_t<fill_ip>> &tcpflow,
    RefFlowMap<address_type_of_t<fill_ip>> &udpflow,
    DecapRefBatch::unrel_type &unrel,
    uint32_t &udpid,
    uint8_t ecn_outer) {
    FlowKey<address_type_of_t<fill_ip>> fk{};
    PacketFlags flags;
    auto res = evaluate_packet<fill_ip>(ippkt, fk, flags, ecn_outer);
    switch (res) {
    case GRO_ADD: {
        auto pkthdr = ippkt.subspan(0, flags.vnethdr.hdr_len);
        auto pktdata = ippkt.subspan(flags.vnethdr.hdr_len);
        append_flow(flags.istcp() ? tcpflow : udpflow, fk, pkthdr, pktdata, flags, udpid);
        break;
    }
    case GRO_NOADD:
        unrel.push_back({const_cast<uint8_t *>(ippkt.data()), ippkt.size()});
        break;
    case GRO_DROP:
        break;
    }
    return res;
}

DecapOutcome DecapRefBatch::push_packet_v4(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel, udpid, ecn_outer);
}

DecapOutcome DecapRefBatch::push_packet_v6(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel, udpid, ecn_outer);
}

DecapOutcome DecapRefBatch::push_packet(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    if (ippkt.size() < sizeof(struct ip))
        return GRO_NOADD;
    if ((ippkt[0] >> 4) == 4)
        return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel, udpid, ecn_outer);
    else if ((ippkt[0] >> 4) == 6)
        return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel, udpid, ecn_outer);
    else
        return GRO_NOADD;
}

void DecapRefBatch::aggregate_udp() {
    // TODO
}

} // namespace wireglider::worker_impl
