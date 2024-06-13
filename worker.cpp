#include <cstdio>
#include <memory>
#include <array>
#include <utility>
#include <linux/ip.h>
#include <fmt/format.h>
#include <tdutil/io.hpp>

#include "worker.hpp"

using namespace tdutil;

namespace wgss {

void worker_func(WorkerArg arg) {
    Worker w(arg);
    w.run();
}

Worker::Worker(const WorkerArg &arg) : _arg(arg) {}

void Worker::run() {
    // there are only 2 file descriptors to watch
    std::array<epoll_event, 2> evbuf;

    _poll.add(_arg.tun->fd(), EPOLLIN);
    _poll.add(_arg.server->fd(), EPOLLIN);

    while (1) {
        auto nevents = _poll.wait(evbuf, -1);
        if (nevents < 0)
            perror("poll error");
        for (int i = 0; i < nevents; i++) {
            if (evbuf[i].events) {
                if (evbuf[i].data.fd == _arg.tun->fd()) {
                    do_tun(&evbuf[i]);
                } else if (evbuf[i].data.fd == _arg.server->fd()) {
                    do_server(&evbuf[i]);
                }
            }
        }
    }
}

void Worker::do_tun(epoll_event *ev) {
    if (ev->events & EPOLLIN) {
        do_tun_read(ev);
    }
}

void Worker::do_tun_read(epoll_event *ev) {
    static std::array<unsigned char, 65536> recvbuf;
    auto msize = read(_arg.tun->fd(), recvbuf.data(), recvbuf.size());
    auto rest = msize;
    // if (msize())
    fmt::print("{}\n", msize);
    if (rest < 0)
        perror("recvmsg");

    if (std::cmp_less(rest, sizeof(virtio_net_hdr)))
        return;
    auto hvnet = reinterpret_cast<virtio_net_hdr *>(&recvbuf[0]);
    rest -= sizeof(virtio_net_hdr);

    if (std::cmp_less(rest, sizeof(iphdr)))
        return;
}

void Worker::do_server(epoll_event *ev) {}

} // namespace wgss
