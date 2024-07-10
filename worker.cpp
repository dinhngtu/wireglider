#include <array>
#include <sys/signalfd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <boost/endian.hpp>
#include <fmt/format.h>

#include "wireglider.hpp"
#include "worker.hpp"

using namespace boost::endian;
using namespace tdutil;
using namespace wireglider::worker_impl;

namespace wireglider {

void worker_func(WorkerArg arg) {
    Worker w(arg);
    w.run();
}

Worker::Worker(const WorkerArg &arg) : _arg(arg) {
    _recvbuf.resize(65536 + sizeof(virtio_net_hdr));
    // max 64 segments
    // 60 bytes ipv4 header + 60 bytes tcp header
    _pktbuf.resize(65536 + 64 * (60 + 60));
}

void Worker::run() {
    auto wn = fmt::format("worker{}", _arg.id);
    pthread_setname_np(pthread_self(), wn.c_str());

    rcu_register_thread();

    sigset_t sigs;
    make_exit_sigset(sigs);
    _sigfd = FileDescriptor(signalfd(-1, &sigs, SFD_NONBLOCK));

    _poll_tun = EPOLLIN;
    _poll.add(_arg.tun->fd(), _poll_tun);
    _poll_server = EPOLLIN;
    _poll.add(_arg.server->fd(), _poll_server);
    _poll.add(_sigfd, EPOLLIN);

    // there are only 3 file descriptors to watch
    std::array<epoll_event, 3> evbuf;

    while (1) {
        auto nevents = _poll.wait(evbuf, 20);
        if (!nevents) {
            rcu_thread_offline();
            nevents = _poll.wait(evbuf, -1);
            rcu_thread_online();
        }
        if (nevents < 0) {
            if (errno == EINTR)
                return;
            else
                perror("poll error");
        }
        try {
            for (int i = 0; i < nevents; i++) {
                if (evbuf[i].events) {
                    if (evbuf[i].data.fd == _arg.tun->fd()) {
                        do_tun(&evbuf[i]);
                    } else if (evbuf[i].data.fd == _arg.server->fd()) {
                        do_server(&evbuf[i]);
                    } else if (evbuf[i].data.fd == _sigfd && (evbuf[i].events & EPOLLIN)) {
                        return;
                    }
                }
            }
        } catch (const QuitException &) {
            kill(getpid(), SIGTERM);
            return;
        }
        rcu_quiescent_state();
    }
}

} // namespace wireglider
