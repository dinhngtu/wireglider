#include <sys/types.h>
#include <csignal>
#include <unistd.h>
#include <sys/uio.h>
#include <fmt/format.h>

#include "worker.hpp"
#include "netutil.hpp"

namespace wireglider {

namespace worker_impl {

outcome::result<void> write_one_batch(int fd, OwnedPacketBatch &opb) {
    std::array<iovec, 3> iov = {
        iovec{&opb.flags.vnethdr, sizeof(opb.flags.vnethdr)},
        iovec{opb.hdrbuf.data(), opb.hdrbuf.size()},
        iovec{},
    };
    while (!opb.buf.empty()) {
        iov[2] = {opb.buf.data(), opb.buf.size()};
        auto written = writev(fd, iov.data(), iov.size());
        if (written < 0) {
            if (is_eagain())
                return fail(EAGAIN);
            else if (errno == EBADFD)
                throw QuitException();
            else
                throw std::system_error(errno, std::system_category(), "write_one_batch writev");
        }
        if (std::cmp_less(written, sizeof(opb.flags.vnethdr) + opb.hdrbuf.size())) {
            // this shouldn't happen but add the handling just in case
            // return std::error_code(EAGAIN, std::system_category());
            throw std::system_error(EAGAIN, std::system_category(), "unexpectedly short tun write");
        }
        opb.buf.erase(opb.buf.begin(), opb.buf.begin() + (written - sizeof(opb.flags.vnethdr) - opb.hdrbuf.size()));
    }
    return outcome::success();
}

template <typename T>
static outcome::result<void> do_tun_write_flowmap(int fd, OwnFlowMap<T> &flows) {
    auto it = flows.begin();
    outcome::result<void> ret = outcome::success();
    for (; it != flows.end(); it++) {
        ret = write_one_batch(fd, it->second);
        if (!ret)
            break;
    }
    if (it != flows.begin())
        flows.erase(flows.begin(), it);
    return ret;
}

outcome::result<void> do_tun_write_unrel(int fd, std::deque<std::vector<uint8_t>> &pkts) {
    virtio_net_hdr vnethdr{};
    vnethdr.flags = 0;
    vnethdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
    while (!pkts.empty()) {
        std::array<iovec, 2> iov = {
            iovec{&vnethdr, sizeof(vnethdr)},
            iovec{pkts.front().data(), pkts.front().size()},
        };
        auto written = writev(fd, iov.data(), iov.size());
        if (written < 0) {
            if (is_eagain())
                return fail(EAGAIN);
            else if (errno == EBADFD)
                throw QuitException();
            else
                throw std::system_error(errno, std::system_category(), "do_tun_write_unrel writev");
        }
        if (std::cmp_less(written, sizeof(vnethdr) + pkts.front().size())) {
            // this shouldn't happen but add the handling just in case
            // return std::error_code(EAGAIN, std::system_category());
            throw std::system_error(EAGAIN, std::system_category(), "unexpectedly short tun write");
        }
        pkts.pop_front();
    }
    return outcome::success();
}

outcome::result<void> do_tun_write_batch(int fd, DecapBatch &batch) {
    BOOST_OUTCOME_TRY(do_tun_write_unrel(fd, batch.unrel));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.tcp4));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.udp4));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.tcp6));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.udp6));
    return outcome::success();
}

} // namespace worker_impl

void Worker::do_tun_requeue_batch(worker_impl::DecapBatch &batch) {
    while (!batch.unrel.empty()) {
        _tununrel.push_back(std::move(batch.unrel.front()));
        batch.unrel.pop_front();
    }
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
}

void Worker::do_tun_write() {
    if (worker_impl::do_tun_write_unrel(_arg.tun->fd(), _tununrel)) {
        while (!_tunwrite.empty()) {
            auto ret = write_one_batch(_arg.tun->fd(), _tunwrite.front());
            if (!ret)
                break;
            _tunwrite.pop_front();
        }
    }
    if (_tunwrite.empty() && _tununrel.empty())
        tun_disable(EPOLLOUT);
    if ((_tunwrite.size() + _tununrel.size()) < 64)
        server_enable(EPOLLIN);
    else
        server_disable(EPOLLIN);
}

} // namespace wireglider
