#include <vector>
#include <variant>
#include <deque>
#include <tdutil/fildes.hpp>
#include <tdutil/epollman.hpp>
#include <tdutil/auto_handle.hpp>
#include <tdutil/srbuf.hpp>

#include "wgss.hpp"
#include "client.hpp"
#include "unix.hpp"
#include "maple_tree.hpp"
#include "result.hpp"

namespace wgss {

struct ControlArg {
    unsigned int ntimers;
    UnixServer *unx;
    ClientTable *clients;
    EndpointTable *client_eps;
    maple_tree *allowed_ips;
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
    tdutil::RingBuffer<2048> buf;
    std::deque<std::string> cmdlines, output;
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

    unsigned int client_timer_id(const x25519_key &k) {
        return std::hash<x25519_key>{}(k) % _arg.ntimers;
    }

private:
    ControlArg _arg;
    tdutil::FileDescriptor _sigfd;
    // dummy just for identifying sockets, do not use
    control_impl::ControlClient _sigfd_client, _unx_client;
    tdutil::EpollManager<tdutil::EpollEventMode::Pointer, control_impl::ControlClient *> _poll;
};

void control_func(ControlArg arg);

} // namespace wgss
