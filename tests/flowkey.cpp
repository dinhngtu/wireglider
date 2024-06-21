#include <boost/endian.hpp>
#include <catch2/catch_test_macros.hpp>

#include "worker/decap.hpp"
#include "packet_tests.hpp"

using namespace boost::endian;

TEST_CASE("flowkey") {
    auto srcip = makeip(192, 0, 2, 10);
    auto dstip = makeip(198, 51, 100, 25);
    tcp4packet pkt{
        .ip =
            {
                .ip_hl = 5,
                .ip_id = 100,
                .ip_p = IPPROTO_TCP,
                .ip_src = srcip,
                .ip_dst = dstip,
            },
        .tcp = {0},
    };
    pkt.tcp.th_sport = 1234;
    pkt.tcp.th_dport = 9876;
    pkt.tcp.th_ack = 9999999;
    pkt.tcp.th_seq = 1000;
}
