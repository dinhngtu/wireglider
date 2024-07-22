#pragma once

#include <array>
#include <mutex>
#include <memory>
#include <boost/unordered/unordered_flat_set.hpp>

#include "proto.hpp"
#include "rundown.hpp"
#include "endpoint.hpp"
#include "netutil.hpp"

namespace wireglider {

// We want the same client to be in both the EP table and the pubkey table.
// Therefore we need a way to have multiple node elements.
// Putting pubkey as EP table value might work but it'll need an extra lookup, which complicates everything.

struct Client {
    struct PubkeyTag {};
    struct EndpointTag {};

    mutable cds_lfht_node pubnode;
    PublicKey pubkey;
    mutable cds_lfht_node epnode;
    ClientEndpoint epkey;

    // readonly
    uint32_t index;
    std::array<uint8_t, 32> psk = {0};
    int keepalive = 0;

    mutable std::mutex mutex;
    // protected by mutex:
    mutable std::unique_ptr<proto::Peer> peer;
    mutable boost::unordered_flat_set<IpRange> allowed_ips;

    // is there a better way to implement this stuff?
    constexpr const PublicKey &key([[maybe_unused]] PubkeyTag tag) const {
        return pubkey;
    }
    constexpr cds_lfht_node &node([[maybe_unused]] PubkeyTag tag) const {
        return pubnode;
    }
    static const Client *get_from(cds_lfht_node *node, [[maybe_unused]] PubkeyTag tag) {
        return caa_container_of(node, Client, pubnode);
    }
    constexpr const ClientEndpoint &key([[maybe_unused]] EndpointTag tag) const {
        return epkey;
    }
    constexpr cds_lfht_node &node([[maybe_unused]] EndpointTag tag) const {
        return epnode;
    }
    static const Client *get_from(cds_lfht_node *node, [[maybe_unused]] EndpointTag tag) {
        return caa_container_of(node, Client, epnode);
    }
};

} // namespace wireglider
