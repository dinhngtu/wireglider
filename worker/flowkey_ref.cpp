#include <memory>
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
struct FlowMapTraits<T, RefFlowMap> {
    static RefFlowMap<T>::mapped_type create_batch(
        std::span<const uint8_t> pkthdr,
        [[maybe_unused]] uint16_t segment_size,
        const PacketFlags &flags) {
        return std::make_unique<PacketRefBatch>(pkthdr, flags);
    }
};

template <auto fill_ip>
static DecapOutcome do_push_packet(
    std::span<const uint8_t> ippkt,
    RefFlowMap<address_type_of_t<fill_ip>> &tcpflow,
    RefFlowMap<address_type_of_t<fill_ip>> &udpflow,
    DecapRefBatch::unrel_type &unrel,
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
        append_flow<address_type_of_t<fill_ip>, RefFlowMap>(
            flags.istcp() ? tcpflow : udpflow,
            fk,
            pkthdr,
            pktdata,
            flags,
            udpid);
        break;
    }
    case GRO_NOADD:
        unrel.push_back({const_cast<uint8_t *>(ippkt.data()), ippkt.size()});
        break;
    case GRO_DROP:
        DBG_PRINT("!! drop\n");
        break;
    }
    return res;
}

DecapOutcome DecapRefBatch::push_packet_v4(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel, udpid, ecn_outer, has_uso);
}

DecapOutcome DecapRefBatch::push_packet_v6(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel, udpid, ecn_outer, has_uso);
}

DecapOutcome DecapRefBatch::push_packet(std::span<const uint8_t> ippkt, uint8_t ecn_outer) {
    if (ippkt.size() < sizeof(struct ip))
        return GRO_NOADD;
    if ((ippkt[0] >> 4) == 4)
        return do_push_packet<fill_fk_ip4>(ippkt, tcp4, udp4, unrel, udpid, ecn_outer, has_uso);
    else if ((ippkt[0] >> 4) == 6)
        return do_push_packet<fill_fk_ip6>(ippkt, tcp6, udp6, unrel, udpid, ecn_outer, has_uso);
    else
        return GRO_NOADD;
}

void DecapRefBatch::aggregate_udp() {
    // TODO
}

} // namespace wireglider::worker_impl
