#pragma once

#include <vector>
#include <utility>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "endpoint.hpp"
#include "worker/offload.hpp"
#include "ancillary.hpp"

namespace wireglider::worker_impl {

struct DecapRecvBatch {
    std::vector<std::vector<uint8_t>> bufs;
    std::vector<iovec> iovs;
    std::vector<mmsghdr> mhs;
    std::vector<std::array<uint8_t, sizeof(sockaddr_in6)>> names;
    std::vector<AncillaryData<uint16_t, uint8_t>> cms;

    std::vector<std::pair<PacketBatch, ClientEndpoint>> pbeps;

    DecapRecvBatch();
    constexpr size_t size() const {
        return 64;
    }
};

} // namespace wireglider::worker_impl
