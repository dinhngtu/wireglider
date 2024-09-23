#pragma once

#include <vector>
#include <span>
#include <sys/uio.h>
#include <tdutil/util.hpp>
#include "liblinux/virtio_net.hpp"

#include "packets.hpp"

#ifdef VIRTIO_NET_HDR_GSO_UDP_L4
#define WIREGLIDER_VIRTIO_NET_HDR_GSO_UDP_L4 VIRTIO_NET_HDR_GSO_UDP_L4
#else
#define WIREGLIDER_VIRTIO_NET_HDR_GSO_UDP_L4 5
#endif

namespace wireglider::worker_impl {

struct PacketBatch {
    std::span<uint8_t> prefix{};
    std::span<uint8_t> data;
    std::span<iovec> unrel{};
    size_t segment_size;
    bool isv6;
    uint8_t ecn;
    constexpr size_t nr_segments() {
        return tdutil::round_up(data.size(), segment_size) / segment_size;
    }
};

static inline PacketBatchIterator begin(PacketBatch &pb) {
    return PacketBatchIterator(pb.segment_size, pb.data.begin(), pb.data.end());
}

static inline PacketBatchIterator end(PacketBatch &pb) {
    return PacketBatchIterator(pb.segment_size, pb.data.end(), pb.data.end());
}

static inline PacketBatchIterator begin(const PacketBatch &pb) {
    return PacketBatchIterator(pb.segment_size, pb.data.begin(), pb.data.end());
}

static inline PacketBatchIterator end(const PacketBatch &pb) {
    return PacketBatchIterator(pb.segment_size, pb.data.end(), pb.data.end());
}

PacketBatch do_tun_gso_split(std::span<uint8_t> inbuf, std::vector<uint8_t> &outbuf, virtio_net_hdr &vnethdr);

} // namespace wireglider::worker_impl
