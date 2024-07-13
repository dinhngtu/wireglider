#include <sys/types.h>
#include <csignal>
#include <unistd.h>
#include <sys/uio.h>
#include <tdutil/io.hpp>

#include "worker.hpp"
#include "netutil.hpp"
#include "dbgprint.hpp"

namespace wireglider {

namespace worker_impl {

outcome::result<void> write_one_batch(int fd, PacketRefBatch &prb) {
    prb.finalize();
    {
        size_t tot = 0;
        for (auto &iov : prb.iov)
            tot += iov.iov_len;
        DBG_PRINT(
            "write prb vnethdr+{}+{}={} bytes: vnethdr {} {} {} {} {} {} {}\n",
            prb.hdrbuf.size(),
            prb.size_bytes(),
            tot,
            prb.flags.vnethdr.flags,
            prb.flags.vnethdr.gso_type,
            prb.flags.vnethdr.hdr_len,
            prb.flags.vnethdr.gso_size,
            prb.flags.vnethdr.csum_start,
            prb.flags.vnethdr.csum_offset,
            prb.flags.istcp() ? "tcp" : "udp");
    }
    while (prb.bytes) {
        auto written = writev(fd, prb.iov.data(), prb.iov.size());
        DBG_PRINT("write_prb {}\n", written);
        if (written < 0) {
            if (is_eagain())
                return fail(EAGAIN);
            else if (errno == EBADFD)
                throw QuitException();
            else
                throw std::system_error(errno, std::system_category(), "write_one_batch writev");
        }
        if (std::cmp_less(written, sizeof(prb.flags.vnethdr) + prb.hdrbuf.size())) {
            // this shouldn't happen but add the handling just in case
            // return std::error_code(EAGAIN, std::system_category());
            throw std::system_error(EAGAIN, std::system_category(), "unexpectedly short tun write");
        }
        auto toadvance = written - sizeof(prb.flags.vnethdr) - prb.hdrbuf.size();
        auto next_pkt_iov = tdutil::advance_iov(std::span(prb.iov).subspan(2), toadvance);
        if (next_pkt_iov.size() != prb.iov.size() - 2) {
            std::copy_backward(next_pkt_iov.begin(), next_pkt_iov.end(), prb.iov.begin() + 2);
            prb.iov.resize(next_pkt_iov.size() + 2);
        }
        prb.bytes -= toadvance;
    }
    return outcome::success();
}

template <typename T>
static outcome::result<void> do_tun_write_flowmap(int fd, RefFlowMap<T> &flows) {
    auto it = flows.begin();
    outcome::result<void> ret = outcome::success();
    for (; it != flows.end(); it++) {
        ret = write_one_batch(fd, *it->second);
        if (!ret)
            break;
    }
    if (it != flows.begin())
        flows.erase(flows.begin(), it);
    return ret;
}

outcome::result<void> do_tun_write_unrel(int fd, DecapRefBatch::unrel_type &pkts) {
    virtio_net_hdr vnethdr{};
    // the peer should have checksummed this packet for us so no need to set NEEDS CSUM
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

outcome::result<void> do_tun_write_batch(int fd, DecapRefBatch &batch) {
    BOOST_OUTCOME_TRY(do_tun_write_unrel(fd, batch.unrel));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.tcp4));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.udp4));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.tcp6));
    BOOST_OUTCOME_TRY(do_tun_write_flowmap(fd, batch.udp6));
    return outcome::success();
}

} // namespace worker_impl

void Worker::do_tun_requeue_batch(worker_impl::DecapRefBatch &batch) {
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
}

} // namespace wireglider
