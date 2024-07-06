#include <cassert>
#include <array>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <tuple>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <catch2/catch_test_macros.hpp>

#include "ancillary.hpp"

using namespace wireglider;

TEST_CASE("ancillary") {
    msghdr mh;
    union {
        std::array<uint8_t, CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(uint8_t))> arr;
        cmsghdr align;
    } _cm = {0};
    mh.msg_control = _cm.arr.data();
    mh.msg_controllen = _cm.arr.size();

    auto cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    uint16_t val16 = 1234;
    memcpy(CMSG_DATA(cm), &val16, sizeof(val16));

    cm = CMSG_NXTHDR(&mh, cm);
    cm->cmsg_level = SOL_IP;
    cm->cmsg_type = IP_TOS;
    cm->cmsg_len = CMSG_LEN(sizeof(uint8_t));
    uint8_t val8 = 1;
    memcpy(CMSG_DATA(cm), &val8, sizeof(val8));

    AncillaryData<uint16_t, uint8_t> cm2(mh);
    cm2.set<0>(SOL_UDP, UDP_SEGMENT, 1234);
    cm2.set<1>(SOL_IP, IP_TOS, 1);

    REQUIRE(std::equal(_cm.arr.begin(), _cm.arr.end(), cm2.begin(), cm2.end()));
}
