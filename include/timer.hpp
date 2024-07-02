#include <vector>
#include <variant>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wshadow"
#include <boost/heap/fibonacci_heap.hpp>
#pragma GCC diagnostic pop
#include <tdutil/fildes.hpp>
#include <tdutil/epollman.hpp>

#include "wgss.hpp"
#include "client.hpp"
#include "maple_tree.hpp"

namespace wgss {

struct TimerArg {
    unsigned int id;
    ClientTable *clients;
};

namespace timer_impl {

struct ClientTimer {
    struct Compare {
        constexpr bool operator()(const ClientTimer &lhs, const ClientTimer &rhs) const {
            return lhs.nexttime > rhs.nexttime;
        }
    };
    using ClientTimerQueue = boost::heap::fibonacci_heap<ClientTimer, boost::heap::compare<ClientTimer::Compare>>;

    x25519_key pubkey;
    mutable uint64_t lasttime, nexttime;
    ClientTimerQueue::handle_type handle;
};

using ClientTimerQueue = ClientTimer::ClientTimerQueue;

} // namespace timer_impl

class TimerWorker {
public:
    TimerWorker(const TimerArg &arg);

    void run();

private:
    void do_timer(epoll_event *ev);
    // void update_period(bool overloaded, uint64_t elapsed);

    // const uint64_t min_period = 100'000'000ull;
    // const uint64_t max_period = 800'000'000ull;

private:
    TimerArg _arg;
    timer_impl::ClientTimerQueue _queue;
    tdutil::FileDescriptor _sigfd;
    tdutil::FileDescriptor _timer;
    uint64_t _period = 100'000'000ull;
    tdutil::EpollManager<> _poll;
    std::vector<uint8_t> _scratch;
};

void timer_func(TimerArg arg);

} // namespace wgss
