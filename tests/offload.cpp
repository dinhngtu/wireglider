#include <vector>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <catch2/catch_test_macros.hpp>
#include <tins/tins.h>

#include "worker.hpp"

using namespace wgss;
using namespace Tins;

TEST_CASE("do_tun_gso_split") {
    std::vector<uint8_t> vec(131072);
    SECTION("tcp4") {
        IP ip("192.0.2.2", "192.0.2.1");
        TCP tcp(1, 1);
        tcp.flags(TCP::ACK | TCP::PSH);
        std::vector<uint8_t> payload(200);
        auto pkt = ip / tcp / RawPDU(payload.begin(), payload.end());
        auto pkt_bytes = pkt.serialize();
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
            .hdr_len = static_cast<__virtio16>(ip.header_size() + tcp.header_size()),
            .gso_size = 100,
            .csum_start = static_cast<__virtio16>(ip.header_size()),
            .csum_offset = offsetof(struct tcphdr, th_sum),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
        REQUIRE(pb.segment_size == 140);
        REQUIRE(pb.data.size() == 2 * 140);
    }

    SECTION("tcp6") {
        IPv6 ip("2001:db8::2", "2001:db8::1");
        TCP tcp(1, 1);
        tcp.flags(TCP::ACK | TCP::PSH);
        std::vector<uint8_t> payload(200);
        auto pkt = ip / tcp / RawPDU(payload.begin(), payload.end());
        auto pkt_bytes = pkt.serialize();
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_TCPV4,
            .hdr_len = static_cast<__virtio16>(ip.header_size() + tcp.header_size()),
            .gso_size = 100,
            .csum_start = static_cast<__virtio16>(ip.header_size()),
            .csum_offset = offsetof(struct tcphdr, th_sum),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
        REQUIRE(pb.segment_size == 160);
        REQUIRE(pb.data.size() == 2 * 160);
    }

    SECTION("udp4") {
        IP ip("192.0.2.2", "192.0.2.1");
        UDP udp(1, 1);
        std::vector<uint8_t> payload(200);
        auto pkt = ip / udp / RawPDU(payload.begin(), payload.end());
        auto pkt_bytes = pkt.serialize();
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
            .hdr_len = static_cast<__virtio16>(ip.header_size() + udp.header_size()),
            .gso_size = 100,
            .csum_start = static_cast<__virtio16>(ip.header_size()),
            .csum_offset = offsetof(struct udphdr, check),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
        REQUIRE(pb.segment_size == 128);
        REQUIRE(pb.data.size() == 2 * 128);
    }

    SECTION("udp6") {
        IPv6 ip("2001:db8::2", "2001:db8::1");
        UDP udp(1, 1);
        std::vector<uint8_t> payload(200);
        auto pkt = ip / udp / RawPDU(payload.begin(), payload.end());
        auto pkt_bytes = pkt.serialize();
        virtio_net_hdr vnethdr{
            .flags = VIRTIO_NET_HDR_F_NEEDS_CSUM,
            .gso_type = VIRTIO_NET_HDR_GSO_UDP_L4,
            .hdr_len = static_cast<__virtio16>(ip.header_size() + udp.header_size()),
            .gso_size = 100,
            .csum_start = static_cast<__virtio16>(ip.header_size()),
            .csum_offset = offsetof(struct udphdr, check),
        };
        auto pb = worker_impl::do_tun_gso_split(pkt_bytes, vec, vnethdr);
        REQUIRE(pb.segment_size == 148);
        REQUIRE(pb.data.size() == 2 * 148);
    }
}
