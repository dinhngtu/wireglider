#pragma once

#include <variant>
#include <utility>
#include <mutex>
#include <vector>
#include <wireguard_ffi.h>
#include "rundown.hpp"
#include "endpoint.hpp"

namespace wgss {

using IpRange = std::variant<std::pair<in_addr, unsigned int>, std::pair<in6_addr, unsigned int>>;

struct Client {
    cds_lfht_node _cds_lfht_node;
    ClientEndpoint _cds_lfht_key;

    // readonly
    uint32_t index;
    ClientEndpoint ep;

    std::mutex mutex;
    // protected by mutex:
    wireguard_tunnel_raw *tunnel;
    std::vector<IpRange> allowed_ips;
};

} // namespace wgss
