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
    // TODO: add udp socket for sending

    itimerspec tmrspec{
        to_timespec(_period),
        to_timespec(_period),
    };
    if (timerfd_settime(_timer, 0, &tmrspec, nullptr) < 0)
        throw std::system_error(errno, std::system_category(), "timerfd_settime");

    std::array<epoll_event, 3> evbuf;
    while (1) {
        auto nevents = _poll.wait(evbuf, -1);
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

void TimerWorker::do_timer(epoll_event *ev) {
    if (!(ev->events & EPOLLIN))
        return;
    uint64_t val;
    if (read(_timer, &val, sizeof(val)) < 0)
        return;
    bool overloaded = false;
    auto now = gettime();
    RundownGuard rcu;
    while (!_queue.empty() && _queue.top().nexttime <= now) {
        // make a copy for mutability
        auto &top = _queue.top();
        if (top.lasttime == now) {
            overloaded = true;
        } else if (!overloaded) {
            // process this client
            auto it = _arg.clients->find(rcu, top.pubkey);
            if (it == _arg.clients->end()) {
                std::lock_guard client_lock(it->mutex);
                auto result = wireguard_tick_raw(it->tunnel, _scratch.data(), _scratch.size());
                switch (result.op) {
                case WRITE_TO_TUNNEL_IPV4:
                case WRITE_TO_TUNNEL_IPV6:
                case WIREGUARD_DONE:
                // TODO
                case WIREGUARD_ERROR:
                // TODO
                default:
                    throw std::runtime_error(
                        fmt::format("unexpected wireguard_tick return {}", static_cast<int>(result.op)));
                }
            } else {
                // TODO: warn?
                _queue.erase(top.handle);
            }
        }
        top.lasttime = now;
        // instead of per-client period, we have global period
        top.nexttime = now + _period;
        _queue.decrease(top.handle);
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
