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
#include "liblinux/virtio_net.hpp"
#include <boost/endian.hpp>
#include <boost/container/flat_map.hpp>

namespace wireglider::worker_impl {

struct PacketFlags {
    using flag_type = std::bitset<4>;
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
    constexpr bool issealed() const {
        return storage[2];
    }
    flag_type::reference issealed() {
        return storage[2];
    }
};

template <typename AddressType>
struct FlowKey {
    using address_type = AddressType;

    AddressType srcip{};
    AddressType dstip{};
    // all below are native order unless otherwise specified
    uint16_t srcport{};
    uint16_t dstport{};
    uint32_t tcpack{};
    uint32_t frag{};
    uint8_t tos{};
    uint8_t ttl{};

    // variable part
    uint16_t segment_size{};
    uint32_t seq{};

    static constexpr size_t variable_offset = offsetof(FlowKey, segment_size);

    bool matches(const FlowKey &other) const {
        static_assert(std::has_unique_object_representations_v<FlowKey>);
        return !memcmp(this, &other, variable_offset);
    }

    bool matches_tcp(const FlowKey &other, size_t size) const {
        return matches(other) && segment_size <= other.segment_size && seq + size == other.seq;
    }

    bool matches_udp(const FlowKey &other) const {
        return matches(other) && segment_size == other.segment_size;
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
    else if (a.segment_size != b.segment_size)
        return a.segment_size <=> b.segment_size;
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

template <typename T, template <typename> typename FlowMap>
static std::pair<typename FlowMap<T>::iterator, bool> find_flow(
    FlowMap<T> &flow,
    const FlowKey<T> &fk,
    std::span<const uint8_t> pktdata,
    const PacketFlags &flags) {
    auto it = flow.lower_bound(fk);
    if (it == flow.end())
        return {it, false};
    if (it->second->flags.ispsh() || it->second->flags.issealed())
        return {it, false};
    if (!it->second->is_appendable(pktdata.size()))
        return {it, false};
    if (flags.istcp() ? !it->first.matches_tcp(fk, pktdata.size()) : !it->first.matches_udp(fk))
        return {it, false};
    return {it, true};
}

} // namespace wireglider::worker_impl
