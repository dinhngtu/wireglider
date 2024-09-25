#include <memory>
#include <system_error>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <fmt/format.h>

#include "client.hpp"
#include "proto.hpp"
#include "wireglider.hpp"
#include "timer.hpp"
#include "netutil.hpp"
#include "rundown.hpp"
#include "worker/send.hpp"
#include "tai64n.hpp"

using namespace tdutil;
using namespace wireglider::proto;
using namespace wireglider::time;
using namespace wireglider::timer_impl;
using namespace wireglider::worker_impl;

namespace wireglider {

void timer_func(TimerArg arg) {
    TimerWorker w(arg);
    w.run();
}

TimerWorker::TimerWorker(const TimerArg &arg) : _arg(arg) {
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

static outcome::result<std::pair<std::span<uint8_t>, ProtoSignal>, EncryptError> unbuffer_packets(
    wireglider::ClientBuffer &top,
    const Client *client,
    boost::strict_lock_ptr<ClientState> &state,
    ServerSendMultilist *tosend,
    std::span<uint8_t> remain,
    const timespec &now) {
    BOOST_OUTCOME_TRY(state->peer->encrypt_begin(now));
    for (auto pkt : top) {
        auto result = BOOST_OUTCOME_TRYX(state->peer->encrypt(remain, pkt));
        auto outsize = result.outsize;
        tosend->push_back({remain.data(), outsize}, client->epkey);
        remain = remain.subspan(outsize);
    }
    return {remain, state->peer->encrypt_end(now)};
}

void TimerWorker::do_timer_step(const Client *client) {
    static thread_local std::vector<uint8_t> scratch(65536);

    auto state = client->state.synchronize();
    auto now = time::gettime(CLOCK_MONOTONIC);

    auto ticksgn = state->peer->tick(now);
    if (!!(ticksgn & ProtoSignal::NeedsQueueClear)) {
        state->buffer.clear_and_dispose(std::default_delete<ClientBuffer>{});
    }
    if (!!(ticksgn & ProtoSignal::SessionWasReset)) {
        return;
    }

    auto tosend = new ServerSendMultilist();
    std::span remain(scratch);
    bool sent_handshake = false, sent_keepalive = false;

    if (!!(ticksgn & ProtoSignal::NeedsHandshake)) {
        auto hs = state->peer->write_handshake1(now, client->pubkey, remain);
        if (hs)
            tosend->push_back({remain.data(), sizeof(Handshake1)}, client->epkey);
        sent_handshake = true;
    } else if (!!(ticksgn & ProtoSignal::NeedsKeepalive)) {
        auto ka = state->peer->encrypt(remain, {});
        if (ka)
            tosend->push_back({remain.data(), ka.assume_value().outsize}, client->epkey);
    }

    while (!state->buffer.empty()) {
        /*
        auto result = wireguard_tick_raw(client->tunnel, scratch.data(), scratch.size());
        if (result.op == WRITE_TO_NETWORK) {
            tosend->push_back(iovec{scratch.data(), result.size}, client->epkey);
        } else if (result.op == WRITE_TO_TUNNEL_IPV4 || result.op == WRITE_TO_TUNNEL_IPV6) {
            fmt::print("got unexpected tunnel write during timer tick");
            break;
        } else {
            break;
        }
         */
        auto &top = state->buffer.front();
        auto result = unbuffer_packets(top, client, state, tosend, remain, now);
        if (!result)
            break;
        ProtoSignal protosgn;
        std::tie(remain, protosgn) = result.assume_value();
        if (!sent_handshake && !!(protosgn & ProtoSignal::NeedsHandshake)) {
            auto hs = state->peer->write_handshake1(now, client->pubkey, remain);
            if (hs)
                tosend->push_back({remain.data(), sizeof(Handshake1)}, client->epkey);
            sent_handshake = true;
        } else if (!sent_keepalive & !!(protosgn & ProtoSignal::NeedsKeepalive)) {
            auto ka = state->peer->encrypt(remain, {});
            if (ka)
                tosend->push_back({remain.data(), ka.assume_value().outsize}, client->epkey);
            sent_keepalive = true;
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
    auto tq = _arg.queue->synchronize();
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
                _sendq.pop_front_and_dispose(std::default_delete<ServerSendBase>{});
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
