#include <system_error>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <fmt/format.h>

#include "wireglider.hpp"
#include "timer.hpp"
#include "netutil.hpp"
#include "rundown.hpp"
#include "worker/send.hpp"
#include "tai64n.hpp"

using namespace tdutil;
using namespace wireglider::time;
using namespace wireglider::timer_impl;
using namespace wireglider::worker_impl;

namespace wireglider {

void timer_func(TimerArg arg) {
    TimerWorker w(arg);
    w.run();
}

TimerWorker::TimerWorker(const TimerArg &arg) : _arg(arg), _scratch(2048) {
}

void TimerWorker::run() {
    auto wn = fmt::format("timer{}", _arg.id);
    pthread_setname_np(pthread_self(), wn.c_str());

    rcu_register_thread();

    sigset_t sigs;
    make_exit_sigset(sigs);
    _sigfd = FileDescriptor(signalfd(-1, &sigs, SFD_NONBLOCK));

    _timer = FileDescriptor(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK));

    _poll.add(_sigfd, EPOLLIN);
    _poll.add(_timer, EPOLLIN | EPOLLET);
    _poll.add(_arg.server->fd(), _poll_server);

    itimerspec tmrspec{
        to_timespec(_period),
        to_timespec(_period),
    };
    if (timerfd_settime(_timer, 0, &tmrspec, nullptr) < 0)
        throw std::system_error(errno, std::system_category(), "timerfd_settime");

    std::array<epoll_event, 3> evbuf;
    while (1) {
        rcu_thread_offline();
        auto nevents = _poll.wait(evbuf, -1);
        rcu_thread_online();
        if (nevents < 0) {
            if (errno == EINTR)
                return;
            else
                perror("poll error");
        }
        for (int i = 0; i < nevents; i++) {
            if (evbuf[i].events) {
                if (evbuf[i].data.fd == _timer)
                    do_timer(&evbuf[i]);
                else if (evbuf[i].data.fd == _arg.server->fd())
                    do_server(&evbuf[i]);
                else if (evbuf[i].data.fd == _sigfd && (evbuf[i].events & EPOLLIN))
                    return;
            }
        }
        rcu_quiescent_state();
    }
}

void TimerWorker::do_timer_step(const Client *client) {
    auto tosend = new ServerSendMultilist();
    {
        auto state = client->state.synchronize();
        auto now = time::gettime(CLOCK_MONOTONIC);
        std::span remain(_scratch);
        while (!state->buffer.empty()) {
            /*
            auto result = wireguard_tick_raw(client->tunnel, _scratch.data(), _scratch.size());
            if (result.op == WRITE_TO_NETWORK) {
                tosend->push_back(iovec{_scratch.data(), result.size}, client->epkey);
            } else if (result.op == WRITE_TO_TUNNEL_IPV4 || result.op == WRITE_TO_TUNNEL_IPV6) {
                fmt::print("got unexpected tunnel write during timer tick");
                break;
            } else {
                break;
            }
             */
            auto &top = state->buffer.front();
            for (auto pkt : top) {
                // TODO
                auto result = state->peer->encrypt(now, remain, pkt);
                if (result) {
                    remain = remain.subspan(result.assume_value().outsize);
                    // protosgn &= result.signal;
                    //  TODO: protosgn
                }
            }
        }
    }
    tosend->finalize();
    if (tosend->send(_arg.server->fd())) {
        delete tosend;
    } else {
        _sendq.push_back(*tosend);
        server_enable(EPOLLOUT);
    }
}

void TimerWorker::do_timer(epoll_event *ev) {
    if (!(ev->events & EPOLLIN))
        return;
    uint64_t val;
    if (read(_timer, &val, sizeof(val)) < 0)
        return;
    bool overloaded = false;
    auto now = gettime64(CLOCK_MONOTONIC);
    RundownGuard rcu;
    auto tq = _arg.queue.queue.synchronize();
    while (!tq->empty() && tq->top().nexttime <= now) {
        bool expired = false;
        // make a copy for mutability
        auto &top = tq->top();
        if (top.lasttime == now) {
            overloaded = true;
        } else if (!overloaded) {
            // process this client
            auto it = _arg.clients->find(rcu, top.pubkey);
            if (it != _arg.clients->end()) {
                do_timer_step(it.get());
            } else {
                expired = true;
            }
        }
        if (expired) {
            tq->erase(top.handle);
        } else {
            top.lasttime = now;
            // instead of per-client period, we have global period
            top.nexttime = now + _period;
            tq->decrease(top.handle);
        }
    }
    // auto done = gettime();
    // update_period(overloaded, done - now);
}

void TimerWorker::do_server(epoll_event *ev) {
    if (ev->events & EPOLLOUT) {
        while (!_sendq.empty()) {
            auto ret = _sendq.front().send(_arg.server->fd());
            if (ret)
                _sendq.pop_front_and_dispose(ServerSendBase::deleter{});
            else
                break;
        }
    }
    if (_sendq.empty())
        server_disable(EPOLLOUT);
}

/*
void TimerWorker::update_period(bool overloaded, uint64_t elapsed) {
    auto newperiod = _period;
    if (overloaded)
        newperiod = std::min(_period * 2, max_period);
    else if (elapsed < _period / 3)
        newperiod = std::max(_period / 2, min_period);

    if (newperiod != _period) {
        _period = newperiod;
        itimerspec tmrspec{
            to_timespec(_period),
            to_timespec(_period),
        };
        if (timerfd_settime(_timer, 0, &tmrspec, nullptr) < 0)
            throw std::system_error(errno, std::system_category(), "timerfd_settime");
    }
}
 */

} // namespace wireglider
