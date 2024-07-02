#include <system_error>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fmt/format.h>

#include "wireglider.hpp"
#include "result.hpp"
#include "control.hpp"
#include "netutil.hpp"
#include "rundown.hpp"

using namespace tdutil;
using namespace wireglider::control_impl;

namespace wireglider {

void control_func(ControlArg arg) {
    ControlWorker w(arg);
    w.run();
}

ControlWorker::ControlWorker(const ControlArg &arg) : _arg(arg) {
}

void ControlWorker::run() {
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
        auto nevents = _poll.wait(evbuf, -1);
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
            _poll.add(cfd, EPOLLIN, client);
        } catch (const std::system_error &) {
            delete client;
            throw;
        }
    }
}

void ControlWorker::do_control_client(epoll_event *ev, ControlClient *client) {
    try {
        if (ev->events & (EPOLLHUP | EPOLLERR)) {
            if (!(ev->events & EPOLLERR)) {
                // TODO: write all pending buffers
            }
            _poll.remove2(client->fd);
            delete client;
        }
        if (ev->events & EPOLLIN) {
            // TODO
            do_client_fill(client);
            if (do_client_getlines(client)) {
                do_cmd(client);
            }
        }
        if (ev->events & EPOLLOUT) {
            // if (...)
            _poll.enable_events(client->fd, EPOLLIN);
        }
    } catch (const ControlClientException &) {
        _poll.remove2(client->fd);
        delete client;
    }
}

void ControlWorker::do_client_fill(ControlClient *client) {
    auto filled = client->buf.fill(client->fd);
    if (filled < 0 && !is_eagain()) {
        _poll.remove2(client->fd);
        delete client;
    } else if (filled == 0) {
        _poll.disable_events(client->fd, EPOLLIN);
    }
}

bool ControlWorker::do_client_getlines(ControlClient *client) {
    auto it = client->buf.begin();
    bool found = false;
    for (; it != client->buf.end(); it++) {
        if (*it == '\n') {
            if (client->cmdlines.back().empty()) {
                found = true;
                break;
            } else {
                client->cmdlines.emplace_back();
                if (client->cmdlines.size() > 256)
                    throw ControlClientException();
            }
        } else if (*it == '\0') {
            throw ControlClientException();
        } else {
            client->cmdlines.back().push_back(*it);
            if (client->cmdlines.back().size() > 256)
                throw ControlClientException();
        }
    }
    client->buf.consume(it - client->buf.begin());
    return found;
}

outcome::result<void> ControlWorker::do_client_write(ControlClient *client) {
    std::vector<iovec> iov;
    for (int i = 0; i < IOV_MAX && i < client->output.size(); i++)
        iov.push_back(iovec{client->output[i].data(), client->output[i].size()});
    if (iov.size()) {
        ssize_t written = writev(client->fd, iov.data(), iov.size());
        if (written < 0)
            return check_eagain(errno, "do_client_write writev");
        else if (written == 0)
            // client closed
            throw ControlClientException();
        std::span<iovec> ranges(iov);
        while (written) {
            size_t now;
            if (ranges.front().iov_len <= written) {
                now = ranges.front().iov_len;
                ranges = ranges.subspan(1);
                client->output.pop_front();
            } else {
                now = written;
                ranges.front().iov_len -= now;
                client->output.front().erase(0, ranges.front().iov_len);
            }
            written -= now;
        }
    }
    return outcome::success();
}

void ControlWorker::do_cmd(ControlClient *client) {
    auto op = client->cmdlines.front();
    client->cmdlines.pop_front();
    if (op == "get=1") {
        do_cmd_get(client);
    } else if (op == "set=1") {
        do_cmd_set(client);
    } else {
        throw ControlClientException();
    }
    client->cmdlines.clear();
}

void ControlWorker::do_cmd_get(ControlClient *client) {
    client->output.emplace_back("errno=0\n");
    client->output.emplace_back("\n");
}

void ControlWorker::do_cmd_set(ControlClient *client) {
    while (!client->cmdlines.empty()) {
        auto &cmd = client->cmdlines.front();
        if (cmd.starts_with("private_key=")) {

        } else {
            client->output.push_back(fmt::format("errno={}\n", ENOSYS));
            client->output.emplace_back("\n");
            return;
        }
    }
}

} // namespace wireglider
