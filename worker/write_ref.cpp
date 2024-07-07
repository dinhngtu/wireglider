#include <sys/types.h>
#include <csignal>
#include <unistd.h>
#include <sys/uio.h>
#include <tdutil/io.hpp>

#include "worker.hpp"
#include "netutil.hpp"

namespace wireglider {

namespace worker_impl {

outcome::result<void> write_opb(int fd, PacketRefBatch &opb) {
    opb.finalize();
    while (opb.bytes) {
        auto written = writev(fd, opb.iov.data(), opb.iov.size());
        if (written < 0) {
            if (is_eagain())
                return fail(EAGAIN);
            else if (errno == EBADFD)
                throw QuitException();
            else
                throw std::system_error(errno, std::system_category(), "write_opb writev");
        }
        if (std::cmp_less(written, sizeof(opb.flags.vnethdr) + opb.hdrbuf.size())) {
            // this shouldn't happen but add the handling just in case
            // return std::error_code(EAGAIN, std::system_category());
            throw std::system_error(EAGAIN, std::system_category(), "unexpectedly short tun write");
        }
        auto toadvance = written - sizeof(opb.flags.vnethdr) - opb.hdrbuf.size();
        auto next_pkt_iov = tdutil::advance_iov(std::span(opb.iov).subspan(2), toadvance);
        if (next_pkt_iov.size() != opb.iov.size() - 2) {
            std::copy_backward(next_pkt_iov.begin(), next_pkt_iov.end(), opb.iov.begin() + 2);
            opb.iov.resize(next_pkt_iov.size() + 2);
        }
        opb.bytes -= toadvance;
    }
    return outcome::success();
}

template <typename T>
static outcome::result<void> do_tun_write_flowmap(int fd, RefFlowMap<T> &flows) {
    auto it = flows.begin();
    outcome::result<void> ret = outcome::success();
    for (; it != flows.end(); it++) {
        ret = write_opb(fd, *it->second);
        if (!ret)
            break;
    }
    if (it != flows.begin())
        flows.erase(flows.begin(), it);
    return ret;
}

outcome::result<void> do_tun_write_unrel(int fd, DecapRefBatch::unrel_type &pkts) {
    virtio_net_hdr vnethdr{};
    vnethdr.flags = 0;
    vnethdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
    while (!pkts.empty()) {
        assert(pkts.front().iov_len);
        std::array<iovec, 2> iov = {
            iovec{&vnethdr, sizeof(vnethdr)},
            pkts.front(),
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
        if (std::cmp_less(written, sizeof(vnethdr) + pkts.front().iov_len)) {
            // this shouldn't happen but add the handling just in case
            // return std::error_code(EAGAIN, std::system_category());
            throw std::system_error(EAGAIN, std::system_category(), "unexpectedly short tun write");
        }
        pkts.pop_front();
    }
    return outcome::success();
}

static outcome::result<void> do_tun_write_batch(int fd, DecapRefBatch &batch) {
    BOOST_OUTCOME_TRY(do_tun_write_unrel(fd, batch.unrel));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.tcp4));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.udp4));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.tcp6));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.udp6));
    return outcome::success();
}

} // namespace worker_impl

outcome::result<void> Worker::do_tun_write_batch(worker_impl::DecapRefBatch &batch) {
    auto ret = worker_impl::do_tun_write_batch(_arg.tun->fd(), batch);
    if (!ret) {
        while (!batch.unrel.empty()) {
            auto base = static_cast<const uint8_t *>(batch.unrel.front().iov_base);
            _tununrel.emplace_back(base, base + batch.unrel.front().iov_len);
            batch.unrel.pop_front();
        }
        for (auto &flow : batch.tcp4)
            if (flow.second->bytes)
                _tunwrite.emplace_back(*flow.second);
        for (auto &flow : batch.udp4)
            if (flow.second->bytes)
                _tunwrite.emplace_back(*flow.second);
        for (auto &flow : batch.tcp6)
            if (flow.second->bytes)
                _tunwrite.emplace_back(*flow.second);
        for (auto &flow : batch.udp6)
            if (flow.second->bytes)
                _tunwrite.emplace_back(*flow.second);
        tun_enable(EPOLLOUT);
    }
    return ret;
}

} // namespace wireglider