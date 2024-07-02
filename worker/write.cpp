#include <sys/types.h>
#include <csignal>
#include <unistd.h>
#include <sys/uio.h>
#include <fmt/format.h>

#include "worker.hpp"
#include "netutil.hpp"

namespace wireglider {

namespace worker_impl {

// returns -errno
static outcome::result<void> write_opb(int fd, OwnedPacketBatch &opb) {
    if (!opb.count)
        return outcome::success();
    std::array<iovec, 3> iov = {
        iovec{&opb.flags.vnethdr, sizeof(opb.flags.vnethdr)},
        iovec{opb.hdrbuf.data(), opb.hdrbuf.size()},
        iovec{opb.buf.data(), opb.buf.size()},
    };
    auto written = writev(fd, iov.data(), iov.size());
    if (written < 0) {
        if (is_eagain())
            return fail(EAGAIN);
        else if (errno == EBADFD)
            throw QuitException();
        else
            throw std::system_error(errno, std::system_category(), "write_opb writev");
    }
    if (std::cmp_less_equal(written, sizeof(opb.flags.vnethdr) + opb.hdrbuf.size()))
        // this shouldn't happen but add the handling just in case
        return std::error_code(EAGAIN, std::system_category());
    opb.buf.erase(opb.buf.begin(), opb.buf.begin() + (written - sizeof(opb.flags.vnethdr) - opb.hdrbuf.size()));
    return outcome::success();
}

template <typename T>
static outcome::result<void> do_tun_write_flowmap(int fd, FlowMap<T> &flows) {
    auto it = flows.begin();
    outcome::result<void> ret = outcome::success();
    for (; it != flows.end(); it++) {
        ret = write_opb(fd, it->second);
        if (!ret)
            break;
    }
    if (it != flows.begin())
        flows.erase(flows.begin(), it);
    return ret;
}

static outcome::result<void> do_tun_write_batch(int fd, DecapBatch &batch) {
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.tcp4));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.udp4));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.tcp6));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.udp6));
    return outcome::success();
}

} // namespace worker_impl

outcome::result<void> Worker::do_tun_write_batch(worker_impl::DecapBatch &batch) {
    auto ret = worker_impl::do_tun_write_batch(_arg.tun->fd(), batch);
    if (!ret) {
        for (auto &flow : batch.tcp4)
            if (flow.second.count)
                _tunwrite.emplace_back(std::move(flow.second));
        for (auto &flow : batch.udp4)
            if (flow.second.count)
                _tunwrite.emplace_back(std::move(flow.second));
        for (auto &flow : batch.tcp6)
            if (flow.second.count)
                _tunwrite.emplace_back(std::move(flow.second));
        for (auto &flow : batch.udp6)
            if (flow.second.count)
                _tunwrite.emplace_back(std::move(flow.second));
        tun_enable(EPOLLOUT);
    }
    return ret;
}

void Worker::do_tun_write() {
    while (!_tunwrite.empty()) {
        auto ret = write_opb(_arg.tun->fd(), _tunwrite.front());
        if (!ret)
            break;
    }
    if (_tunwrite.empty())
        tun_disable(EPOLLOUT);
    else if (_tunwrite.size() < 64)
        server_enable(EPOLLIN);
    else
        server_disable(EPOLLIN);
}

} // namespace wireglider
