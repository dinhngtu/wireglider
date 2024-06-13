#pragma once

#include <memory>
#include <mutex>
#include <tdutil/epollman.hpp>
#include <wireguard_ffi.h>
#include <tins/tins.h>
#include <boost/unordered/concurrent_flat_map.hpp>
#include <xxhash.h>

#include "tun.hpp"
#include "udpsock.hpp"

namespace boost {

static inline std::size_t hash_value(const Tins::IPv4Address &a) {
    return a;
}

static inline std::size_t hash_value(const Tins::IPv6Address &a) {
    return XXH3_64bits(a.begin(), a.address_size);
}

} // namespace boost

namespace wgss {

struct WorkerArg {
    Tun *tun;
    UdpServer *server;
    bool tun_v6;
    bool srv_v6;
};

using ClientAddress = std::variant<Tins::IPv4Address, Tins::IPv6Address>;

struct Client {
    uint32_t index;
    struct {
        std::mutex mutex;
        wireguard_tunnel *tunnel;
    };
};

class Worker {
public:
    Worker(const WorkerArg &arg);

    void run();

private:
    void do_tun(epoll_event *ev);
    void do_tun_read(epoll_event *ev);
    void do_server(epoll_event *ev);

private:
    WorkerArg _arg;
    tdutil::EpollManager<> _poll;
    boost::concurrent_flat_map<ClientAddress, Client> _clients;
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wgss
