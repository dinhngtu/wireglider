#include <catch2/catch_test_macros.hpp>

#include "worker.hpp"
#include "packet_tests.hpp"

using namespace wgss;
using namespace Tins;
using enum wgss::worker_impl::DecapBatch::Outcome;

static const IPv4Address ip4a("192.0.2.1"), ip4b("192.0.2.2"), ip4c("192.0.2.3");
static const IPv6Address ip6a("2001:db8::1"), ip6b("2001:db8::2"), ip6c("2001:db8::3");

static void push_one(
    worker_impl::DecapBatch &batch,
    std::vector<uint8_t> pkt,
    worker_impl::DecapBatch::Outcome outcome = GRO_ADDED) {
    auto res = batch.push_packet(std::span<const uint8_t>(pkt));
    REQUIRE(res == outcome);
}

template <typename AddressType>
static void check_flow(
    typename worker_impl::FlowMap<AddressType>::iterator it,
    AddressType src,
    AddressType dst,
    uint32_t segment_size,
    uint32_t seq,
    size_t count) {
    REQUIRE(it->first.srcip == src);
    REQUIRE(it->first.dstip == dst);
    REQUIRE(it->first.segment_size == segment_size);
    REQUIRE(it->first.seq == seq);
    REQUIRE(it->second.count == count);
    REQUIRE(it->second.buf.size() == count * segment_size);
}

template <typename IPType, typename L4Type>
static std::vector<uint8_t> flip_l4_csum(std::vector<uint8_t> pkt) {
    auto l4hdr = reinterpret_cast<L4Type *>(&pkt[sizeof(IPType)]);
    l4hdr->check = ~l4hdr->check;
    return pkt;
}

TEST_CASE("DecapBatch multiple protocols and flows") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));     // tcp4 flow 1
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));                  // udp4 flow 1
    push_one(batch, make_udp<IP>(ip4a, 1, ip4c, 1, 100));                  // udp4 flow 2
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101));   // tcp4 flow 1
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4c, 1, TCP::ACK, 100, 201));   // tcp4 flow 2
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 1));   // tcp6 flow 1
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 101)); // tcp6 flow 1
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6c, 1, TCP::ACK, 100, 201)); // tcp6 flow 2
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));                  // udp4 flow 1
    push_one(batch, make_udp<IPv6>(ip6a, 1, ip6b, 1, 100));                // udp6 flow 1
    push_one(batch, make_udp<IPv6>(ip6a, 1, ip6b, 1, 100));                // udp6 flow 1

    REQUIRE(batch.tcp4.size() == 2);
    {
        worker_impl::FlowKey<in_addr> fk{
            to_addr(ip4a),
            to_addr(ip4b),
            1,
            1,
            100,
            0,
            1,
        };
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, to_addr(ip4a), to_addr(ip4b), 100, 1, 2);

        REQUIRE(it != batch.tcp4.begin());
        it--;
        check_flow(it, to_addr(ip4a), to_addr(ip4c), 100, 201, 1);
    }

    REQUIRE(batch.udp4.size() == 2);
    {
        worker_impl::FlowKey<in_addr> fk{
            to_addr(ip4a),
            to_addr(ip4b),
            1,
            1,
            100,
            0,
            0,
        };
        auto it = batch.udp4.lower_bound(fk);
        REQUIRE(it != batch.udp4.end());
        check_flow(it, to_addr(ip4a), to_addr(ip4b), 100, 0, 2);

        REQUIRE(it != batch.udp4.begin());
        it--;
        check_flow(it, to_addr(ip4a), to_addr(ip4c), 100, 1, 1);
    }

    REQUIRE(batch.tcp6.size() == 2);
    {
        worker_impl::FlowKey<in6_addr> fk{
            to_addr(ip6a),
            to_addr(ip6b),
            1,
            1,
            100,
            0,
            1,
        };
        auto it = batch.tcp6.lower_bound(fk);
        REQUIRE(it != batch.tcp6.end());
        check_flow(it, to_addr(ip6a), to_addr(ip6b), 100, 1, 2);

        REQUIRE(it != batch.tcp6.begin());
        it--;
        check_flow(it, to_addr(ip6a), to_addr(ip6c), 100, 201, 1);
    }

    REQUIRE(batch.udp6.size() == 1);
    {
        worker_impl::FlowKey<in6_addr> fk{
            to_addr(ip6a),
            to_addr(ip6b),
            1,
            1,
            100,
            0,
            0,
        };
        auto it = batch.udp6.lower_bound(fk);
        REQUIRE(it != batch.udp6.end());
        check_flow(it, to_addr(ip6a), to_addr(ip6b), 100, 0, 2);
    }
}

TEST_CASE("DecapBatch PSH interleaved") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));                // v4 flow 1
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK | TCP::PSH, 100, 101));   // v4 flow 1
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 201));              // v4 flow 1
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 301));              // v4 flow 1
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 1));              // v6 flow 1
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK | TCP::PSH, 100, 101)); // v6 flow 1
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 201));            // v6 flow 1
    push_one(batch, make_tcp<IPv6>(ip6a, 1, ip6b, 1, TCP::ACK, 100, 301));            // v6 flow 1

    REQUIRE(batch.tcp4.size() == 2);
    {
        worker_impl::FlowKey<in_addr> fk{
            to_addr(ip4a),
            to_addr(ip4b),
            1,
            1,
            100,
            0,
            1,
        };
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, to_addr(ip4a), to_addr(ip4b), 100, 1, 2);
    }
    {
        worker_impl::FlowKey<in_addr> fk{
            to_addr(ip4a),
            to_addr(ip4b),
            1,
            1,
            100,
            0,
            201,
        };
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, to_addr(ip4a), to_addr(ip4b), 100, 201, 2);
    }

    REQUIRE(batch.tcp6.size() == 2);
    {
        worker_impl::FlowKey<in6_addr> fk{
            to_addr(ip6a),
            to_addr(ip6b),
            1,
            1,
            100,
            0,
            1,
        };
        auto it = batch.tcp6.lower_bound(fk);
        REQUIRE(it != batch.tcp6.end());
        check_flow(it, to_addr(ip6a), to_addr(ip6b), 100, 1, 2);
    }
    {
        worker_impl::FlowKey<in6_addr> fk{
            to_addr(ip6a),
            to_addr(ip6b),
            1,
            1,
            100,
            0,
            201,
        };
        auto it = batch.tcp6.lower_bound(fk);
        REQUIRE(it != batch.tcp6.end());
        check_flow(it, to_addr(ip6a), to_addr(ip6b), 100, 201, 2);
    }
}

TEST_CASE("DecapBatch coalesceItemInvalidCSum") {
    worker_impl::DecapBatch batch;

    push_one(
        batch,
        flip_l4_csum<struct ip, tcphdr>(make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1)),
        GRO_NOADD);                                                      // v4 flow 1 seq 1 len 100
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101)); // v4 flow 1 seq 101 len 100
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 201)); // v4 flow 1 seq 201 len 100
    push_one(batch, flip_l4_csum<struct ip, udphdr>(make_udp<IP>(ip4a, 1, ip4b, 1, 100)), GRO_NOADD);
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));
    push_one(batch, make_udp<IP>(ip4a, 1, ip4b, 1, 100));

    REQUIRE(batch.tcp4.size() == 1);
    {
        worker_impl::FlowKey<in_addr> fk{
            to_addr(ip4a),
            to_addr(ip4b),
            1,
            1,
            100,
            0,
            UINT32_MAX,
        };
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, to_addr(ip4a), to_addr(ip4b), 100, 101, 2);
    }

    REQUIRE(batch.udp4.size() == 1);
    {
        worker_impl::FlowKey<in_addr> fk{
            to_addr(ip4a),
            to_addr(ip4b),
            1,
            1,
            100,
            0,
            UINT32_MAX,
        };
        auto it = batch.udp4.lower_bound(fk);
        REQUIRE(it != batch.udp4.end());
        check_flow(it, to_addr(ip4a), to_addr(ip4b), 100, 0, 2);
    }

    REQUIRE(batch.unrel.size() == 2);
}

TEST_CASE("DecapBatch out of order") {
    worker_impl::DecapBatch batch;

    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 101)); // v4 flow 1 seq 101 len 100
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 1));   // v4 flow 1 seq 1 len 100
    push_one(batch, make_tcp<IP>(ip4a, 1, ip4b, 1, TCP::ACK, 100, 201)); // v4 flow 1 seq 201 len 100

    REQUIRE(batch.tcp4.size() == 1);
    {
        worker_impl::FlowKey<in_addr> fk{
            to_addr(ip4a),
            to_addr(ip4b),
            1,
            1,
            100,
            0,
            1,
        };
        auto it = batch.tcp4.lower_bound(fk);
        REQUIRE(it != batch.tcp4.end());
        check_flow(it, to_addr(ip4a), to_addr(ip4b), 100, 1, 3);
    }
}
