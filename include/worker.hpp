#pragma once

#include <memory>
#include <tdutil/epollman.hpp>
#include <wireguard_ffi.h>

#include "tun.hpp"
#include "udpsock.hpp"

namespace wgss {

struct WorkerArg {
    Tun *tun;
    UdpServer *server;
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
};

// this function forces all worker allocations to happen within its own thread
void worker_func(WorkerArg arg);

} // namespace wgss
