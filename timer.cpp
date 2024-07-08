#include <system_error>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <fmt/format.h>

#include "wireglider.hpp"
#include "timer.hpp"
#include "netutil.hpp"
#include "rundown.hpp"

using namespace tdutil;
using namespace wireglider::timer_impl;

namespace wireglider {

void timer_func(TimerArg arg) {
    TimerWorker w(arg);
    w.run();
}

constexpr uint64_t to_time(time_t sec, long nsec) {
    return static_cast<uint64_t>(sec) + static_cast<uint64_t>(nsec) * 1'000'000'000;
}

constexpr timespec to_timespec(uint64_t tm) {
    return timespec{
        static_cast<time_t>(tm / 1'000'000'000),
        static_cast<long>(tm % 1'000'000'000),
    };
}

static uint64_t gettime() {
    timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        throw std::system_error(errno, std::system_category(), "clock_gettime");
    return to_time(ts.tv_sec, ts.tv_nsec);
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
    _poll.add(_arg.server->fd(), 0);

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
                else if (evbuf[i].data.fd == _sigfd && (evbuf[i].events & EPOLLIN))
                    return;
            }
        }
        rcu_quiescent_state();
    }
}

void TimerWorker::do_timer_step(ClientTable::iterator &it) {
    while (1) {
        auto result = wireguard_tick_raw(it->tunnel, _scratch.data(), _scratch.size());
        switch (result.op) {
        case WRITE_TO_NETWORK: {
            const sockaddr *sa;
            size_t sz;
            if (auto sin = std::get_if<sockaddr_in>(&it->epkey)) {
                sa = reinterpret_cast<const sockaddr *>(sin);
                sz = sizeof(*sin);
            } else if (auto sin6 = std::get_if<sockaddr_in6>(&it->epkey)) {
                sa = reinterpret_cast<const sockaddr *>(sin6);
                sz = sizeof(*sin6);
            } else {
                tdutil::unreachable();
            }
            sendto(_arg.server->fd(), _scratch.data(), result.size, 0, sa, sz);
            break;
        }
        case WIREGUARD_DONE:
            return;
        case WRITE_TO_TUNNEL_IPV4:
        case WRITE_TO_TUNNEL_IPV6:
            // shouldn't happen during timer ticks
            fmt::print("got unexpected tunnel write during timer tick");
            return;
        case WIREGUARD_ERROR:
            // TODO: ignore for now
            return;
        default:
            throw std::runtime_error(fmt::format("unexpected wireguard_tick return {}", static_cast<int>(result.op)));
        }
    }
}

void TimerWorker::do_timer(epoll_event *ev) {
    if (!(ev->events & EPOLLIN))
        return;
    uint64_t val;
    if (read(_timer, &val, sizeof(val)) < 0)
        return;
    bool overloaded = false;
    auto now = gettime();
    RundownGuard rcu;
    std::lock_guard lock(_arg.queue->mutex);
    while (!_arg.queue->queue.empty() && _arg.queue->queue.top().nexttime <= now) {
        bool expired = false;
        // make a copy for mutability
        auto &top = _arg.queue->queue.top();
        if (top.lasttime == now) {
            overloaded = true;
        } else if (!overloaded) {
            // process this client
            auto it = _arg.clients->find(rcu, top.pubkey);
            if (it != _arg.clients->end()) {
                std::lock_guard client_lock(it->mutex);
                do_timer_step(it);
            } else {
                expired = true;
            }
        }
        if (expired) {
            _arg.queue->queue.erase(top.handle);
        } else {
            top.lasttime = now;
            // instead of per-client period, we have global period
            top.nexttime = now + _period;
            _arg.queue->queue.decrease(top.handle);
        }
    }
    // auto done = gettime();
    // update_period(overloaded, done - now);
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
