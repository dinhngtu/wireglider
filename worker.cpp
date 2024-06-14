#include <array>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <boost/endian.hpp>

#include "worker.hpp"

using namespace boost::endian;
using namespace tdutil;
using namespace wgss::worker_impl;

namespace wgss {

void worker_func(WorkerArg arg) {
    Worker w(arg);
    w.run();
}

Worker::Worker(const WorkerArg &arg) : _arg(arg) {
    _overhead = calc_overhead(_arg.srv_is_v6);
    _recvbuf.resize(65536 + sizeof(virtio_net_hdr));
    // max 64 segments
    _pktbuf.resize(65536 + 64 * (sizeof(ip) + sizeof(tcphdr)));
    _sendbuf.resize(65536 + 64 * (sizeof(ip) + sizeof(tcphdr)) + 64 * _overhead);
}

void Worker::run() {
    auto wn = fmt::format("worker{}", _arg.id);
    pthread_setname_np(pthread_self(), wn.c_str());

    rcu_register_thread();

    _poll.add(_arg.tun->fd(), EPOLLIN);
    _poll.add(_arg.server->fd(), EPOLLIN);

    // there are only 2 file descriptors to watch
    std::array<epoll_event, 2> evbuf;

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
        rcu_quiescent_state();
    }
}

} // namespace wgss
