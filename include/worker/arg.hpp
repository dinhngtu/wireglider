#pragma once

#include "wireglider.hpp"
#include "tun.hpp"
#include "udpsock.hpp"
#include "liblinux/maple_tree.hpp"
#include "rundown.hpp"

namespace wireglider {

struct WorkerArg {
    unsigned int id;
    bool tun_has_uso;
    Tun *tun;
    UdpServer *server;
    ConfigRef _config;
    ClientTable *clients;
    EndpointTable *client_eps;
    maple_tree *allowed_ip4, *allowed_ip6;

    const Config *config([[maybe_unused]] RundownGuard &rcu) const {
        return _config.load(std::memory_order_acquire);
    }
};

} // namespace wireglider
