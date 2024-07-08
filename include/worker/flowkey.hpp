#pragma once

#include <cassert>
#include <bitset>
#include <vector>
#include <span>
#include <deque>
#include <type_traits>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "virtio_net.hpp"
#include <boost/endian.hpp>
#include <boost/container/flat_map.hpp>

namespace wireglider::worker_impl {

struct PacketFlags {
    using flag_type = std::bitset<3>;
    virtio_net_hdr vnethdr{};
    flag_type storage;
    constexpr bool isv6() const {
        return storage[0];
    }
    flag_type::reference isv6() {
        return storage[0];
    }
    constexpr bool istcp() const {
        return storage[1];
    }
    flag_type::reference istcp() {
        return storage[1];
    }
    constexpr bool ispsh() const {
        return storage[2];
    }
    flag_type::reference ispsh() {
        return storage[2];
    }
};

template <typename AddressType>
struct FlowKey {
    using address_type = AddressType;

    AddressType srcip;
    AddressType dstip;
    // all below are native order unless otherwise specified
    uint16_t srcport;
    uint16_t dstport;
    uint16_t segment_size;
    uint8_t tos;
    uint8_t ttl;
    uint32_t tcpack;

    // variable part
    uint32_t seq;

    // NOTE: reordering to tcpack-tos-ttl-segment_size breaks our tests
    // need to see what's happening and why we needed to reorder in the first place
    // normally we only depend on ordering of `seq` so the reordering shouldn't have broken anything...

    static constexpr size_t variable_offset = offsetof(FlowKey, seq);

    bool matches(const FlowKey &other) const {
        static_assert(std::has_unique_object_representations_v<FlowKey>);
        return !memcmp(this, &other, variable_offset);
    }

    bool is_consecutive_with(const FlowKey &other, size_t size) const {
        return this->matches(other) && this->seq + size == other.seq;
    }
};

template <typename AddressType>
static inline bool operator==(const FlowKey<AddressType> &a, const FlowKey<AddressType> &b) noexcept {
    static_assert(std::has_unique_object_representations_v<FlowKey<AddressType>>);
    return !memcmp(&a, &b, sizeof(a));
}

template <typename AddressType>
static inline auto operator<=>(const FlowKey<AddressType> &a, const FlowKey<AddressType> &b) noexcept {
    static_assert(std::has_unique_object_representations_v<FlowKey<AddressType>>);
    auto prefix = memcmp(&a, &b, FlowKey<AddressType>::variable_offset);
    if (prefix > 0)
        return std::strong_ordering::greater;
    else if (prefix < 0)
        return std::strong_ordering::less;
    else
        return a.seq <=> b.seq;
}

enum DecapOutcome {
    GRO_ADD,
    GRO_NOADD,
    GRO_DROP,
};

static inline auto format_as(DecapOutcome o) {
    static const std::array<std::string, 3> outcomes = {"GRO_ADD", "GRO_NOADD", "GRO_NOADD"};
    return outcomes[o];
}

} // namespace wireglider::worker_impl
