#pragma once

#include <algorithm>
#include <variant>
#include <utility>
#include <mutex>
#include <vector>
#include <wireguard_ffi.h>
#include "rundown.hpp"
#include "endpoint.hpp"

namespace wireglider {

using IpRange = std::variant<std::pair<in_addr, unsigned int>, std::pair<in6_addr, unsigned int>>;

// We want the same client to be in both the EP table and the pubkey table.
// Therefore we need a way to have multiple node elements.
// Putting pubkey as EP table value might work but it'll need an extra lookup, which complicates everything.

struct Client {
    struct PubkeyTag {};
    struct EndpointTag {};

    cds_lfht_node pubnode;
    x25519_key pubkey;
    cds_lfht_node epnode;
    ClientEndpoint epkey;

    // readonly
    uint32_t index;

    std::mutex mutex;
    // protected by mutex:
    wireguard_tunnel_raw *tunnel;
    std::vector<IpRange> allowed_ips;

    // is there a better way to implement this stuff?
    constexpr x25519_key &key([[maybe_unused]] PubkeyTag tag) {
        return pubkey;
    }
    constexpr cds_lfht_node &node([[maybe_unused]] PubkeyTag tag) {
        return pubnode;
    }
    static Client *get_from(cds_lfht_node *node, [[maybe_unused]] PubkeyTag tag) {
        return caa_container_of(node, Client, pubnode);
    }
    constexpr ClientEndpoint &key([[maybe_unused]] EndpointTag tag) {
        return epkey;
    }
    constexpr cds_lfht_node &node([[maybe_unused]] EndpointTag tag) {
        return epnode;
    }
    static Client *get_from(cds_lfht_node *node, [[maybe_unused]] EndpointTag tag) {
        return caa_container_of(node, Client, epnode);
    }
};

} // namespace wireglider

namespace std {
template <>
struct hash<x25519_key> {
    size_t operator()(const x25519_key &a) const noexcept {
        return XXH3_64bits(&a.key[0], sizeof(a.key));
    }
};
} // namespace std

static constexpr bool operator==(const x25519_key &a, const x25519_key &b) noexcept {
    return std::equal(std::begin(a.key), std::end(a.key), std::begin(b.key));
}

static constexpr auto operator<=>(const x25519_key &a, const x25519_key &b) noexcept {
    return std::lexicographical_compare_three_way(
        std::begin(a.key),
        std::end(a.key),
        std::begin(b.key),
        std::end(b.key));
}
