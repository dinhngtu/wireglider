#include <utility>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/endian.hpp>
#include <tdutil/util.hpp>
#include <tdutil/io.hpp>

#include "worker.hpp"
#include "worker/evaluator.hpp"

using namespace boost::endian;
using namespace wireglider::worker_impl;
using enum DecapOutcome;

namespace wireglider::worker_impl {

OwnedPacketBatch::OwnedPacketBatch(const PacketRefBatch &prb)
    : hdrbuf(prb.hdrbuf.begin(), prb.hdrbuf.end()), flags(prb.flags) {
    size_t totsize = 0;
    auto pkts = std::span(prb.iov).subspan(2);
    for (const auto &pkt : pkts) {
        totsize += pkt.iov_len;
        count++;
    }
    buf.resize(totsize);
    tdutil::memgather(buf.data(), totsize, pkts);
}

template <typename T>
struct FlowMapTraits<T, OwnFlowMap> {
    static OwnFlowMap<T>::mapped_type create_batch(
        std::span<const uint8_t> pkthdr,
        uint16_t segment_size,
        const PacketFlags &flags) {
        return OwnedPacketBatch(pkthdr, 4u * segment_size, flags);
    }
};

template <auto fill_ip>
static DecapOutcome do_push_packet(
    std::span<const uint8_t> ippkt,
    OwnFlowMap<address_type_of_t<fill_ip>> &tcpflow,
    OwnFlowMap<address_type_of_t<fill_ip>> &udpflow,
    std::deque<std::vector<uint8_t>> &unrel,
    uint32_t &udpid,
    uint8_t ecn_outer,
    bool has_uso) {
    FlowKey<address_type_of_t<fill_ip>> fk{};
    PacketFlags flags;
    auto res = evaluate_packet<fill_ip>(ippkt, fk, flags, ecn_outer, has_uso);
    switch (res) {
    case GRO_ADD: {
        auto pkthdr = ippkt.subspan(0, flags.vnethdr.hdr_len);
        auto pktdata = ippkt.subspan(flags.vnethdr.hdr_len);
        append_flow<address_type_of_t<fill_ip>, OwnFlowMap>(
            flags.istcp() ? tcpflow : udpflow,
            fk,
            pkthdr,
            pktdata,
            flags,
            udpid);
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

DecapOutcome DecapBatch::push_packet_v4(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel, udpid, ecn_outer, has_uso);
}

DecapOutcome DecapBatch::push_packet_v6(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel, udpid, ecn_outer, has_uso);
}

DecapOutcome DecapBatch::push_packet(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    if (ippkt.size() < sizeof(struct ip))
        return GRO_NOADD;
    if ((ippkt[0] >> 4) == 4)
        return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel, udpid, ecn_outer, has_uso);
    else if ((ippkt[0] >> 4) == 6)
        return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel, udpid, ecn_outer, has_uso);
    else
        return GRO_NOADD;
}

void DecapBatch::aggregate_udp() {
    // TODO
}

} // namespace wireglider::worker_impl
