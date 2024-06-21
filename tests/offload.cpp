#include <vector>
#include <catch2/catch_test_macros.hpp>

#include "worker.hpp"
#include "packet_tests.hpp"

using namespace wgss;

TEST_CASE("offload") {
    std::vector<uint8_t> vec(65536);
    auto srcip = makeip(192, 0, 2, 1);
    auto dstip = makeip(192, 0, 2, 2);
    SECTION("tcp4") {
        auto pkt = make_tcp4(200, srcip, dstip, 1, 1, 1, TH_ACK | TH_PUSH);
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
            .hdr_len = sizeof(tcp4packet),
            .gso_size = 100,
            .csum_start = sizeof(struct ip),
            .csum_offset = offsetof(struct tcphdr, th_sum),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt->to_span(), vec, vnethdr);
        REQUIRE(pb.segment_size == 140);
        REQUIRE(pb.nr_segments() == 2);
    }
    SECTION("udp4") {
        auto pkt = make_udp4(200, srcip, dstip, 1, 1);
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
            .hdr_len = sizeof(udp4packet),
            .gso_size = 100,
            .csum_start = sizeof(struct ip),
            .csum_offset = offsetof(struct udphdr, check),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt->to_span(), vec, vnethdr);
        REQUIRE(pb.segment_size == 128);
        REQUIRE(pb.nr_segments() == 2);
    }
}
