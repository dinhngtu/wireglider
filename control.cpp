#include <string>
#include <system_error>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <boost/unordered/unordered_flat_set.hpp>
#include <fmt/format.h>

#include "wireglider.hpp"
#include "result.hpp"
#include "control.hpp"
#include "netutil.hpp"
#include "rundown.hpp"
#include "dbgprint.hpp"

using namespace tdutil;
using namespace wireglider::control_impl;
using namespace wireglider::proto;

namespace wireglider {

void control_func(ControlArg arg) {
    ControlWorker w(arg);
    w.run();
}

ControlWorker::ControlWorker(const ControlArg &arg)
    : _arg(arg),
      _client_idx(MTREE_INIT(client_idx, MT_FLAGS_ALLOC_RANGE | MT_FLAGS_LOCK_EXTERN | MT_FLAGS_ALLOC_WRAPPED)) {
}

void ControlWorker::run() {
    DBG_PRINT("control thread {}\n", pthread_self());
    pthread_setname_np(pthread_self(), "control");

    rcu_register_thread();

    sigset_t sigs;
    make_exit_sigset(sigs);
    _sigfd = FileDescriptor(signalfd(-1, &sigs, SFD_NONBLOCK));

    _poll.add(_sigfd, EPOLLIN, &_sigfd_client);
    _poll.add(_arg.unx->fd(), EPOLLIN, &_unx_client);

    if (listen(_arg.unx->fd(), 100) < 0)
        throw std::system_error(errno, std::system_category(), "listen(AF_UNIX)");

    std::array<epoll_event, 16> evbuf;
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
        try {
            for (int i = 0; i < nevents; i++) {
                if (evbuf[i].events) {
                    auto state = static_cast<ControlClient *>(evbuf[i].data.ptr);
                    if (state == &_unx_client)
                        do_control_accept(&evbuf[i]);
                    else if (state == &_sigfd_client && (evbuf[i].events & EPOLLIN))
                        return;
                    else
                        do_control_client(&evbuf[i], state);
                }
            }
        } catch (const QuitException &) {
            kill(getpid(), SIGTERM);
            return;
        }
        rcu_quiescent_state();
    }
}

void ControlWorker::do_control_accept(epoll_event *ev) {
    if (ev->events & (EPOLLHUP | EPOLLERR)) {
        throw QuitException();
    }
    if (ev->events & EPOLLIN) {
        auto cfd = accept(_arg.unx->fd(), nullptr, nullptr);
        if (cfd < 0)
            std::ignore = check_eagain();
        auto client = new ControlClient(cfd);
        try {
            _poll.add(cfd, EPOLLIN | EPOLLRDHUP, client);
        } catch (const std::system_error &) {
            delete client;
            throw;
        }
    }
}

void ControlWorker::do_control_client(epoll_event *ev, ControlClient *client) {
    try {
        if (ev->events & (EPOLLHUP | EPOLLERR))
            throw ControlClientException();
        if (ev->events & EPOLLRDHUP) {
            if (do_client_write(client))
                // there's no error here but throw ControlClientException to conveniently close the client
                throw ControlClientException();
            else
                _poll.enable_events(client->fd, EPOLLOUT);
        } else if (ev->events & EPOLLOUT) {
            if (do_client_write(client))
                _poll.disable_events(client->fd, EPOLLOUT);
            else
                _poll.disable_events(client->fd, EPOLLIN);
        }
        if (ev->events & EPOLLIN) {
            do_client_fill(client);
            if (do_client_getlines(client)) {
                do_cmd(client);
                if (do_client_write(client))
                    _poll.disable_events(client->fd, EPOLLOUT);
                else
                    _poll.set_events2(client->fd, EPOLLOUT);
            }
        }
    } catch (const ControlClientException &) {
        _poll.remove2(client->fd);
        delete client;
    }
}

void ControlWorker::do_client_fill(ControlClient *client) {
    auto filled = client->buf.fill(client->fd);
    if (filled < 0 && !is_eagain()) {
        throw ControlClientException();
    } else if (filled == 0) {
        _poll.disable_events(client->fd, EPOLLIN);
    }
}

bool ControlWorker::do_client_getlines(ControlClient *client) {
    auto it = client->buf.begin();
    bool found = false;
    for (; it != client->buf.end(); it++) {
        if (*it == '\n') {
            if (client->input.back().empty()) {
                client->input.pop_back();
                found = true;
                break;
            } else {
                client->input.emplace_back();
                // max 1024 lines per command
                if (client->input.size() > 1024)
                    throw ControlClientException();
            }
        } else if (*it == '\0') {
            throw ControlClientException();
        } else {
            if (client->input.empty())
                client->input.emplace_back();
            client->input.back().push_back(*it);
            // max 256 chars per command line
            if (client->input.back().size() > 256)
                throw ControlClientException();
        }
    }
    client->buf.consume(it - client->buf.begin());
    return found;
}

outcome::result<void> ControlWorker::do_client_write(ControlClient *client) {
    while (!client->output.empty()) {
        std::vector<iovec> iov;
        for (size_t i = 0; i < IOV_MAX && i < client->output.size(); i++)
            iov.push_back(iovec{client->output[i].data(), client->output[i].size()});
        ssize_t written = writev(client->fd, iov.data(), iov.size());
        if (written < 0)
            return check_eagain(errno, "do_client_write writev");
        else if (written == 0)
            // client closed
            throw ControlClientException();
        while (written) {
            size_t now;
            if (std::cmp_less_equal(client->output.front().size(), written)) {
                now = client->output.front().size();
                client->output.pop_front();
            } else {
                now = written;
                client->output.front().erase(0, now);
            }
            written -= now;
        }
    }
    return outcome::success();
}

void ControlWorker::do_cmd(ControlClient *client) {
    auto op = client->input.front();
    client->input.pop_front();
    try {
        if (op == "get=1") {
            do_cmd_get(client);
        } else if (op == "set=1") {
            do_cmd_set(client);
        } else {
            throw ControlClientException();
        }
    } catch (const ControlCommandException &ex) {
        client->output.emplace_back(fmt::format("errno={}\n\n", ex.err));
    } catch (const std::exception &) {
        client->output.emplace_back(fmt::format("errno={}\n\n", EPERM));
    }
    client->input.clear();
}

void ControlWorker::do_cmd_get(ControlClient *client) {
    client->output.emplace_back("errno=0\n\n");
}

static std::vector<ClientSetCommand> parse_set(std::deque<std::string> &input, InterfaceCommand &iface_cmd) {
    std::vector<ClientSetCommand> cmds;
    while (!input.empty()) {
        auto &cmd = input.front();
        if (cmd.starts_with("private_key=")) {
            auto privkey = cmd.substr(sizeof("private_key=") - 1);
            if (!parse_keybytes(iface_cmd.private_key.key, privkey.c_str()))
                throw ControlCommandException(EINVAL);
            iface_cmd.has_privkey = true;
        } else if (cmd.starts_with("listen_port=")) {
            // ignore
        } else if (cmd.starts_with("fwmark=")) {
            // ignore
        } else if (cmd == "replace_peers=true") {
            iface_cmd.replace_peers = true;
        } else if (cmd.starts_with("public_key=")) {
            cmds.emplace_back();
            auto psk = cmd.substr(sizeof("public_key=") - 1);
            if (!parse_keybytes(cmds.back().public_key.key, psk.c_str()))
                throw ControlCommandException(EINVAL);
        } else if (cmd.starts_with("protocol_version=")) {
            // ignore
        } else if (!cmds.empty()) {
            if (cmd == "remove=true") {
                cmds.back().remove = true;
            } else if (cmd == "update_only=true") {
                cmds.back().update_only = true;
            } else if (cmd.starts_with("preshared_key=")) {
                auto psk_str = cmd.substr(sizeof("preshared_key=") - 1);
                uint8_t psk[32];
                if (!parse_keybytes(psk, psk_str.c_str()))
                    throw ControlCommandException(EINVAL);
                cmds.back().preshared_key = std::to_array(psk);
            } else if (cmd.starts_with("endpoint=")) {
                auto ep_str = cmd.substr(sizeof("endpoint=") - 1);
                auto ep = parse_ipport(ep_str.c_str());
                if (std::holds_alternative<std::monostate>(ep))
                    throw ControlCommandException(EINVAL);
                else if (auto sin = std::get_if<sockaddr_in>(&ep))
                    cmds.back().endpoint = *sin;
                else if (auto sin6 = std::get_if<sockaddr_in6>(&ep))
                    cmds.back().endpoint = *sin6;
            } else if (cmd.starts_with("persistent_keepalive_interval=")) {
                auto keepalive_str = cmd.substr(sizeof("persistent_keepalive_interval=") - 1);
                int keepalive = atoi(keepalive_str.c_str());
                if (keepalive < 0 || keepalive > 65535)
                    throw ControlCommandException(EINVAL);
                cmds.back().persistent_keepalive_interval = keepalive;
            } else if (cmd == "replace_allowed_ips=true") {
                cmds.back().replace_allowed_ips = true;
            } else if (cmd.starts_with("allowed_ip=")) {
                auto aip = cmd.substr(sizeof("allowed_ip=") - 1);
                auto parsed = parse_iprange(aip.c_str());
                if (auto net4 = std::get_if<IpRange4>(&parsed))
                    cmds.back().allowed_ip.push_back(*net4);
                else if (auto net6 = std::get_if<IpRange6>(&parsed))
                    cmds.back().allowed_ip.push_back(*net6);
                else
                    throw ControlCommandException(EINVAL);
            } else {
                throw ControlCommandException(ENOSYS);
            }
        } else {
            throw ControlCommandException(ENOSYS);
        }
        input.pop_front();
    }
    return cmds;
}

uint32_t ControlWorker::alloc_client_id(Client *client) {
    unsigned long id, next;
    MA_STATE(mas, &_client_idx, 0, 0);
    auto ret = mas_alloc_cyclic(&mas, &id, client, 1, (1ul << 24) - 1, &next, 0);
    if (ret < 0)
        throw ControlCommandException(-ret);
    return mas.index;
}

void ControlWorker::free_client_id(uint32_t id) {
    MA_STATE(mas, &_client_idx, id, id);
    mas_erase(&mas);
}

void ControlWorker::do_cmd_set(ControlClient *cc) {
    int ret = 0;
    InterfaceCommand iface_cmd;
    auto cmds = parse_set(cc->input, iface_cmd);
    // std::vector<Client> newpeers;

    if (iface_cmd.has_privkey)
        do_cmd_set_privkey(iface_cmd);

    std::deque<const Client *> todelete;
    try {
        RundownGuard rcu;

        if (iface_cmd.replace_peers) {
            MA_STATE(mas, &_client_idx, 0, 0);
            void *entry;
            mas_for_each(&mas, entry, ULONG_MAX) {
                todelete.push_back(static_cast<Client *>(entry));
            }

            do_cmd_flush_tables(rcu);
            for (auto &tq : *_arg.timerq) {
                std::lock_guard lock(tq.mutex);
                tq.queue.clear();
            }
        }

        auto config = _arg._config.load(std::memory_order_acquire);
        for (auto &cmd : cmds) {
            const Client *old = nullptr;
            if (cmd.remove)
                old = do_remove_client(rcu, config, cmd.public_key);
            else
                old = do_add_client(rcu, config, cmd);
            if (old)
                todelete.push_back(old);
        }
    } catch (const ControlCommandException &ex) {
        ret = ex.err;
    }

    if (!todelete.empty()) {
        synchronize_rcu();
        for (auto p : todelete) {
            if (!iface_cmd.replace_peers)
                free_client_id(p->index);
            delete p;
        }
    }

    cc->output.emplace_back(fmt::format("errno=0\n\n", ret));
}

void ControlWorker::do_cmd_set_privkey(const InterfaceCommand &iface_cmd) {
    RundownGuard rcu;
    auto config = new Config();
    wireglider::Config *oldconfig;
    while (1) {
        oldconfig = _arg._config.load(std::memory_order_acquire);
        config->privkey = iface_cmd.private_key;
        config->prefix4 = oldconfig->prefix4;
        config->prefix6 = oldconfig->prefix6;
        if (_arg._config.compare_exchange_weak(oldconfig, config, std::memory_order_release))
            break;
    }
    call_rcu(&oldconfig->rcu, Config::rcu_deleter);
}

void ControlWorker::do_cmd_flush_tables(RundownGuard &rcu) {
    MA_STATE(mas, &_client_idx, 0, ULONG_MAX);
    mas_store(&mas, nullptr);

    int ret;
    ret = mtree_store_range(_arg.allowed_ip4, 0, ULONG_MAX, nullptr, 0);
    if (ret < 0)
        throw std::system_error(-ret, std::generic_category(), "mtree_store_range allowed_ip4");
    ret = mtree_store_range(_arg.allowed_ip6, 0, ULONG_MAX, nullptr, 0);
    if (ret < 0)
        throw std::system_error(-ret, std::generic_category(), "mtree_store_range allowed_ip6");

    _arg.client_eps->clear(rcu);
    _arg.clients->clear(rcu);
}

const Client *ControlWorker::do_remove_client(RundownGuard &rcu, Config *config, const PublicKey &public_key) {
    auto it = _arg.clients->find(rcu, public_key);
    if (it != _arg.clients->end()) {
        auto oldclient = it.get();
        const Client *replaced;
        // none of this should fail
        for (auto aip : oldclient->allowed_ips) {
            if (auto net4 = std::get_if<IpRange4>(&aip)) {
                replaced = static_cast<Client *>(mtree_erase(_arg.allowed_ip4, config->prefix4.reduce(net4->first)));
                if (replaced != oldclient)
                    throw std::runtime_error("unexpected mtree_erase allowed_ip4 result");
            } else if (auto net6 = std::get_if<IpRange6>(&aip)) {
                replaced = static_cast<Client *>(mtree_erase(_arg.allowed_ip6, config->prefix6.reduce(net6->first)));
                if (replaced != oldclient)
                    throw std::runtime_error("unexpected mtree_erase allowed_ip6 result");
            }
        }
        if (!_arg.client_eps->erase_at(rcu, oldclient))
            throw std::runtime_error("client_eps->erase_at");
        if (!_arg.clients->erase(rcu, it))
            throw std::runtime_error("clients->erase");
        return oldclient;
    } else {
        return nullptr;
    }
}

const Client *ControlWorker::do_add_client(RundownGuard &rcu, Config *config, ClientSetCommand &cmd) {
    /*
    auto oldclient = do_remove_client(rcu, config, cmd.public_key);
    if (!oldclient && cmd.update_only)
        return nullptr;
    else if (oldclient)
        return oldclient;
     */

    auto it = _arg.clients->find(rcu, cmd.public_key);
    if (cmd.update_only && it == _arg.clients->end())
        throw ControlCommandException(ENOENT);
    auto oldclient = it.get();
    if (!oldclient) {
        if (!cmd.endpoint)
            throw ControlCommandException(EINVAL);
        if (!cmd.preshared_key)
            cmd.preshared_key = std::array<uint8_t, 32>();
        if (!cmd.persistent_keepalive_interval)
            cmd.persistent_keepalive_interval = 0;
    }

    if (cmd.endpoint) {
        auto epit = _arg.client_eps->find(rcu, *cmd.endpoint);
        if (epit != _arg.client_eps->end() && epit.get() != oldclient)
            throw ControlCommandException(EEXIST);
    }

    auto newclient = new Client();
    newclient->index = alloc_client_id(newclient);
    try {
        newclient->pubkey = cmd.public_key;
        newclient->epkey = cmd.endpoint.value_or(oldclient->epkey);
        newclient->psk = cmd.preshared_key.value_or(oldclient->psk);
        newclient->keepalive = cmd.persistent_keepalive_interval.value_or(oldclient->keepalive);
        if (!oldclient || cmd.replace_allowed_ips) {
            newclient->allowed_ips = boost::unordered_flat_set<IpRange>(cmd.allowed_ip.begin(), cmd.allowed_ip.end());
        } else {
            newclient->allowed_ips = oldclient->allowed_ips;
            newclient->allowed_ips.insert(cmd.allowed_ip.begin(), cmd.allowed_ip.end());
        }
        DBG_PRINT("adding peer endpoint {} = {}\n", newclient->epkey, static_cast<void *>(newclient));
        newclient->peer = std::make_unique<Peer>(newclient->index);

        // we're the only writer to client/ep/aip tables
        // so we're free to do rmw existence checking here
        const Client *replaced;
        {
            replaced = _arg.clients->replace(rcu, newclient);
            if (replaced != oldclient)
                throw std::runtime_error("unexpected clients->replace result");
        }
        {
            // endpoint may change so newclient may be in a different slot from oldclient
            if (oldclient)
                if (!_arg.client_eps->erase_at(rcu, oldclient))
                    throw std::runtime_error("client_eps->erase_at");
            _arg.client_eps->replace(rcu, newclient);
        }
        std::vector<unsigned long> inserted4, inserted6;
        try {
            for (auto aip : newclient->allowed_ips) {
                if (auto net4 = std::get_if<IpRange4>(&aip)) {
                    auto [begin, end] = config->prefix4.get_range(net4->first, net4->second);
                    DBG_PRINT("allowed ip4 range {}-{}\n", begin, end);
                    auto ret = mtree_insert_range(_arg.allowed_ip4, begin, end, newclient, 0);
                    if (ret < 0)
                        throw ControlCommandException(-ret);
                    inserted4.push_back(begin);
                } else if (auto net6 = std::get_if<IpRange6>(&aip)) {
                    auto [begin, end] = config->prefix6.get_range(net6->first, net6->second);
                    DBG_PRINT("allowed ip6 range {}-{}\n", begin, end);
                    auto ret = mtree_insert_range(_arg.allowed_ip6, begin, end, newclient, 0);
                    if (ret < 0)
                        throw ControlCommandException(-ret);
                    inserted6.push_back(begin);
                }
            }
        } catch (const ControlCommandException &) {
            for (auto begin4 : inserted4)
                mtree_erase(_arg.allowed_ip4, begin4);
            for (auto begin6 : inserted6)
                mtree_erase(_arg.allowed_ip6, begin6);
            throw;
        }

        {
            auto tmrid = client_timer_id(cmd.public_key);
            auto tq = &(*_arg.timerq)[tmrid];
            std::lock_guard lock(tq->mutex);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
            timer_impl::ClientTimer tmr{
                .pubkey = cmd.public_key,
                .lasttime = 0,
                .nexttime = 0, // top of the timer queue
                .handle = timer_impl::ClientTimer::ClientTimerQueue::handle_type(nullptr),
            };
#pragma GCC diagnostic pop
            auto handle = tq->queue.push(tmr);
            (*handle).handle = handle;
        }

    } catch (const ControlCommandException &) {
        free_client_id(newclient->index);
        delete newclient;
        throw;
    }
    DBG_PRINT(
        "add ok, newclient={}, oldclient={}\n",
        static_cast<void *>(newclient),
        static_cast<const void *>(oldclient));

    return oldclient;
}

} // namespace wireglider
