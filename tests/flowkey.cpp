#include <vector>
#include <memory>
#include <catch2/catch_test_macros.hpp>
#include <tins/tins.h>

#include "worker.hpp"

using namespace Tins;

std::vector<uint8_t> tcp4_packet(
    const char *src,
    uint16_t sport,
    const char *dst,
    uint16_t dport,
    uint16_t tcpflags,
    uint32_t segment_size,
    uint32_t seq) {
    IP ip(dst, src);
    TCP tcp(dport, sport);
    tcp.flags(tcpflags);
    std::vector<uint8_t> payload(segment_size);
    auto pkt = ip / tcp / RawPDU(payload);
    return pkt.serialize();
}

TEST_CASE("flowkey") {
    wgss::worker_impl::DecapBatch batch;

    SECTION("multiple protocols and flows") {
        std::vector<std::vector<uint8_t>> pkts;
        auto pkt = tcp4_packet("192.0.2.1", 1, "192.0.2.2", 1, TCP::ACK, 100, 1);
        batch.push_packet_v4(pkt);
    }
}
