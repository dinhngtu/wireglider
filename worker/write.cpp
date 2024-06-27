#include <sys/uio.h>
#include <fmt/format.h>

#include "worker.hpp"
#include "netutil.hpp"

namespace wgss {

namespace worker_impl {

// returns -errno
static int write_opb(int fd, OwnedPacketBatch &opb) {
    std::array<iovec, 3> iov = {
        iovec{&opb.flags.vnethdr, sizeof(opb.flags.vnethdr)},
        iovec{opb.hdrbuf.data(), opb.hdrbuf.size()},
        iovec{opb.buf.data(), opb.buf.size()},
    };
    auto written = writev(fd, iov.data(), iov.size());
    if (written < 0)
        return -errno;
    if (std::cmp_less_equal(written, sizeof(opb.flags.vnethdr) + opb.hdrbuf.size()))
        // this shouldn't happen but add the handling just in case
        return -EAGAIN;
    opb.buf.erase(opb.buf.begin(), opb.buf.begin() + (written - sizeof(opb.flags.vnethdr) - opb.hdrbuf.size()));
    return 0;
}

template <typename T>
static int do_tun_write_flowmap(int fd, FlowMap<T> &flows) {
    auto it = flows.begin();
    int ret = 0;
    for (; it != flows.end(); it++) {
        ret = write_opb(fd, it->second);
        if (is_eagain(-ret))
            break;
        else if (ret < 0)
            throw std::system_error(-ret, std::system_category(), "write_opb");
    }
    if (it != flows.begin())
        flows.erase(flows.begin(), it);
    return ret;
}

static int do_tun_write_batch(int fd, DecapBatch &batch) {
    int ret;
    if ((ret = do_tun_write_flowmap(fd, batch.tcp4)) < 0)
        return ret;
    if ((ret = do_tun_write_flowmap(fd, batch.udp4)) < 0)
        return ret;
    if ((ret = do_tun_write_flowmap(fd, batch.tcp6)) < 0)
        return ret;
    if ((ret = do_tun_write_flowmap(fd, batch.udp6)) < 0)
        return ret;
    return 0;
}

} // namespace worker_impl

void Worker::do_tun_write_batch(worker_impl::DecapBatch &batch) {
    auto ret = worker_impl::do_tun_write_batch(_arg.tun->fd(), batch);
    if (is_eagain(ret)) {
        for (auto &flow : batch.tcp4)
            _tunwrite.emplace_back(std::move(flow.second));
        for (auto &flow : batch.udp4)
            _tunwrite.emplace_back(std::move(flow.second));
        for (auto &flow : batch.tcp6)
            _tunwrite.emplace_back(std::move(flow.second));
        for (auto &flow : batch.udp6)
            _tunwrite.emplace_back(std::move(flow.second));
        tun_enable(EPOLLOUT);
    }
}

void Worker::do_tun_write() {
    while (!_tunwrite.empty()) {
        auto ret = write_opb(_arg.tun->fd(), _tunwrite.front());
        if (is_eagain(-ret)) {
            break;
        } else {
            if (ret < 0)
                fmt::print("do_server_send: {}\n", strerrordesc_np(ret));
            _tunwrite.pop_front();
        }
    }
    if (_tunwrite.empty())
        tun_disable(EPOLLOUT);
    else if (_tunwrite.size() < 64)
        server_enable(EPOLLIN);
    else
        server_disable(EPOLLIN);
}

} // namespace wgss
