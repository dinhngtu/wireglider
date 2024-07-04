#pragma once

#include <atomic>
#include <vector>
#include <optional>
#include <variant>
#include <deque>
#include <boost/container/stable_vector.hpp>
#include <tdutil/fildes.hpp>
#include <tdutil/epollman.hpp>
#include <tdutil/auto_handle.hpp>
#include <tdutil/srbuf.hpp>
#include <wireguard_ffi.h>

#include "endpoint.hpp"
#include "wireglider.hpp"
#include "client.hpp"
#include "unix.hpp"
#include "maple_tree.hpp"
#include "result.hpp"
#include "timer.hpp"

namespace wireglider {

using ConfigRef = std::atomic_ref<Config *>;

struct ControlArg {
    ConfigRef _config;
    UnixServer *unx;
    ClientTable *clients;
    EndpointTable *client_eps;
    maple_tree *allowed_ip4, *allowed_ip6;
    const boost::container::stable_vector<timer_impl::TimerQueue> *timerq;
};

namespace control_impl {

struct ControlClientException : std::exception {};

struct ControlClient {
    ControlClient() {
    }
    ControlClient(tdutil::FileDescriptor &&_fd) : fd(std::move(_fd)) {
    }
    tdutil::FileDescriptor fd;
    uint32_t events;
    tdutil::RingBuffer<4096> buf;
    std::deque<std::string> input, output;
};

struct InterfaceCommand {
    x25519_key private_key;
    bool has_privkey = false;
    bool replace_peers = false;
};

struct ClientSetCommand {
    // std::string public_key;
    x25519_key public_key;
    bool remove = false;
    bool update_only = false;
    std::optional<std::array<uint8_t, 32>> preshared_key;
    std::optional<ClientEndpoint> endpoint;
    std::optional<int> persistent_keepalive_interval = 0;
    bool replace_allowed_ips = false;
    std::vector<IpRange> allowed_ip;
};

struct ControlCommandException : std::exception {
    explicit ControlCommandException(int _err) : err(_err) {
    }
    int err = 0;
};

} // namespace control_impl

class ControlWorker {
public:
    ControlWorker(const ControlArg &arg);

    void run();

private:
    void do_control_accept(epoll_event *ev);
    void do_control_client(epoll_event *ev, control_impl::ControlClient *client);
    void do_client_fill(control_impl::ControlClient *client);
    bool do_client_getlines(control_impl::ControlClient *client);
    outcome::result<void> do_client_write(control_impl::ControlClient *client);
    void do_cmd(control_impl::ControlClient *client);
    void do_cmd_get(control_impl::ControlClient *client);
    void do_cmd_set(control_impl::ControlClient *client);
    void do_cmd_set_privkey(const control_impl::InterfaceCommand &iface_cmd);
    void do_cmd_flush_tables(RundownGuard &rcu);
    Client *do_remove_client(RundownGuard &rcu, Config *config, const x25519_key &public_key);
    // returns **old** client to delete
    Client *do_add_client(RundownGuard &rcu, Config *config, control_impl::ClientSetCommand &cmd);

    unsigned int client_timer_id(const x25519_key &k) const {
        return std::hash<x25519_key>{}(k) % _arg.timerq->size();
    }

    uint32_t alloc_client_id(Client *client);
    void free_client_id(uint32_t id);

private:
    ControlArg _arg;
    tdutil::FileDescriptor _sigfd;
    // dummy just for identifying sockets, do not use
    control_impl::ControlClient _sigfd_client, _unx_client;
    tdutil::EpollManager<tdutil::EpollEventMode::Pointer, control_impl::ControlClient *> _poll;
    maple_tree _client_idx;
};

void control_func(ControlArg arg);

} // namespace wireglider
