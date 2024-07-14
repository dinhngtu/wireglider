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

    /*
     * there are only 3 file descriptors to watch
     * quoting David Laight
     * (https://lore.kernel.org/netdev/bc84e68c0980466096b0d2f6aec95747@AcuMS.aculab.com/t/#m3711a1d5c751ac9484e955e6df525583efd4b4a3):
     * > For poll() it doesn't make much difference how many fd are supplied to each system call.
     * > The overall performance is much the same for 32, 64 or 500 (all the sockets).
     * > For epoll_wait() that isn't true.
     * > Supplying a buffer that is shorter than the list of 'ready' fds gives a massive penalty.
     * > With a buffer long enough for all the events epoll() is somewhat faster than poll().
     * > But with a 64 entry buffer it is much slower.
     * > I've looked at the code and can't see why splicing the unread events back is expensive.
     */
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
            do_poll_reset();
        } catch (const QuitException &) {
            kill(getpid(), SIGTERM);
            return;
        }
        rcu_quiescent_state();
    }
}

void Worker::do_poll_reset() {
    if (_tunwrite.empty() && _tununrel.empty())
        tun_disable(EPOLLOUT);
    if ((_tunwrite.size() + _tununrel.size()) < 64)
        server_enable(EPOLLIN);
    else
        server_disable(EPOLLIN);

    if (_serversend.empty())
        server_disable(EPOLLOUT);
    if (_serversend.size() < 64)
        tun_enable(EPOLLIN);
    else
        tun_disable(EPOLLIN);
}

} // namespace wireglider
