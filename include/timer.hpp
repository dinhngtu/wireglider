#pragma once

#include <vector>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <boost/heap/fibonacci_heap.hpp>
#pragma GCC diagnostic pop
#include <boost/thread/synchronized_value.hpp>
#include <tdutil/fildes.hpp>
#include <tdutil/epollman.hpp>

#include "wireglider.hpp"
#include "udpsock.hpp"
#include "worker/send.hpp"

namespace wireglider {

namespace timer_impl {

struct ClientTimer {
    struct Compare {
        constexpr bool operator()(const ClientTimer &lhs, const ClientTimer &rhs) const {
            return lhs.nexttime > rhs.nexttime;
        }
    };
    using ClientTimerQueue = boost::heap::fibonacci_heap<ClientTimer, boost::heap::compare<ClientTimer::Compare>>;

    PublicKey pubkey;
    mutable uint64_t lasttime, nexttime;
    ClientTimerQueue::handle_type handle;
};

struct TimerQueue {
    mutable boost::synchronized_value<timer_impl::ClientTimer::ClientTimerQueue> queue;
};

} // namespace timer_impl

struct TimerArg {
    unsigned int id;
    ClientTable *clients;
    timer_impl::TimerQueue queue;
    UdpServer *server;
};

class TimerWorker {
public:
    TimerWorker(const TimerArg &arg);

    void run();

private:
    void do_timer(epoll_event *ev);
    void do_timer_step(const Client *client);
    // void update_period(bool overloaded, uint64_t elapsed);

    void do_server(epoll_event *ev);

    // const uint64_t min_period = 100'000'000ull;
    // const uint64_t max_period = 800'000'000ull;

    void server_disable(uint32_t events) {
        auto newevents = _poll_server & ~events;
        if (newevents != _poll_server) {
            _poll.set_events(_arg.server->fd(), newevents);
            _poll_server = newevents;
        }
    }

    void server_enable(uint32_t events) {
        auto newevents = _poll_server | events;
        if (newevents != _poll_server) {
            _poll.set_events(_arg.server->fd(), newevents);
            _poll_server = newevents;
        }
    }

private:
    TimerArg _arg;
    tdutil::FileDescriptor _sigfd;
    tdutil::FileDescriptor _timer;
    uint64_t _period = 100'000'000ull;
    tdutil::EpollManager<> _poll;
    std::vector<uint8_t> _scratch;
    worker_impl::ServerSendQueue _sendq;
    uint32_t _poll_server = 0;
};

void timer_func(TimerArg arg);

} // namespace wireglider
