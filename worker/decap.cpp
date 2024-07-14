#include <sys/types.h>
#include <csignal>

#include "worker.hpp"
#include "ancillary.hpp"
#include "dbgprint.hpp"

using namespace wireglider::worker_impl;

namespace wireglider {

namespace worker_impl {

static constexpr const bool use_opb_mainloop = false;

DecapRecvBatch::DecapRecvBatch() : iovs(size()), mhs(size()), names(size()), cms(size()) {
    bufs.reserve(64);
    for (size_t i = 0; i < size(); i++) {
        auto &buf = bufs.emplace_back(65536);
        iovs[i] = {buf.data(), buf.size()};
        mhs[i].msg_hdr.msg_name = names[i].data();
        mhs[i].msg_hdr.msg_namelen = names[i].size();
        mhs[i].msg_hdr.msg_iov = &iovs[i];
        mhs[i].msg_hdr.msg_iovlen = 1;
        cms[i] = AncillaryData<uint16_t, uint8_t>(mhs[i].msg_hdr);
        mhs[i].msg_hdr.msg_flags = 0;
    }
}

enum class ServerRecvMethod {
    Recvmsg,
    Recvmmsg,
};

static constexpr const ServerRecvMethod server_recv_method = ServerRecvMethod::Recvmsg;
static constexpr const bool server_recv_once = true;

} // namespace worker_impl

void Worker::do_server(epoll_event *ev) {
    static thread_local DecapRecvBatch recvbatch;
    static thread_local std::vector<uint8_t> decapbuf(65536);

    if (ev->events & (EPOLLHUP | EPOLLERR)) {
        throw std::system_error(EIO, std::system_category(), "do_server events");
    }
    if (ev->events & EPOLLOUT)
        do_server_send();
    if (ev->events & EPOLLIN) {
        while (1) {
            auto nvecs = do_server_recv(ev, recvbatch);
            if (nvecs <= 0)
                break;

            // recvbatch.pbeps is already set to the correct size
            for (auto &[pb, ep] : recvbatch.pbeps) {
                auto batch = do_server_decap_ref(pb, ep, decapbuf);
                if (!batch) {
                    DBG_PRINT("decap failed\n");
                    continue;
                } else {
                    DBG_PRINT(
                        "got decap batch size v4 {} {} v6 {} {} unrel/retpkt {} {}\n",
                        batch->tcp4.size(),
                        batch->udp4.size(),
                        batch->tcp6.size(),
                        batch->udp6.size(),
                        batch->unrel.size(),
                        batch->retpkt.size());
                }

                auto ret = server_send_reflist(batch->retpkt, ep);
                if (ret.has_value()) {
                    auto tosend = new ServerSendList(ep);
                    for (auto &iov : ret.value())
                        tosend->push_back(iov);
                    tosend->finalize();
                    _serversend.push_back(*tosend);
                }

                if (!worker_impl::do_tun_write_batch(_arg.tun->fd(), *batch))
                    do_tun_requeue_batch(*batch);
            }
            if constexpr (server_recv_once)
                break;
        }
    }
}

int Worker::do_server_recv([[maybe_unused]] epoll_event *ev, DecapRecvBatch &drb) {
    int nvecs;
    if constexpr (server_recv_method == ServerRecvMethod::Recvmsg) {
        nvecs = 1;
        auto bytes = recvmsg(_arg.server->fd(), &drb.mhs[0].msg_hdr, 0);
        auto e = errno;
        if (bytes < 0) {
            if (is_eagain(e))
                return 0;
            else
                throw std::system_error(e, std::system_category(), "do_server_recv recvmsg");
        }
        drb.mhs[0].msg_len = static_cast<unsigned int>(bytes);
    } else if constexpr (server_recv_method == ServerRecvMethod::Recvmmsg) {
        // with upstream Linux, passing in a zero timeout massively improves the performance of recvmmsg() even in
        // nonblocking mode at the cost of receiving only one datagram per call
        // the reason is that recvmmsg() simply calls recvmsg() in a loop, then calls cond_resched() every message (??)
        // it also checks timeout every datagram so a zero timeout makes it effectively equivalent to recvmsg()
        // also passing MSG_DONTWAIT gives an extra 5% performance or so (!?)
        nvecs = recvmmsg(_arg.server->fd(), drb.mhs.data(), drb.mhs.size(), MSG_DONTWAIT, nullptr);
        auto e = errno;
        if (nvecs < 0) {
            if (is_eagain(e))
                return 0;
            else
                throw std::system_error(e, std::system_category(), "do_server_recv recvmsg");
        }
    } else {
        tdutil::unreachable();
    }

    drb.pbeps.clear();
    for (auto i = 0; i < nvecs; i++) {
        size_t gro_size = static_cast<size_t>(drb.mhs[i].msg_len);
        uint8_t ecn = 0;
        for (auto cm = CMSG_FIRSTHDR(&drb.mhs[i].msg_hdr); cm; cm = CMSG_NXTHDR(&drb.mhs[i].msg_hdr, cm)) {
            if (cm->cmsg_type == UDP_GRO) {
                int tmp;
                memcpy(&tmp, CMSG_DATA(cm), sizeof(tmp));
                gro_size = tmp;
            } else if (cm->cmsg_type == IP_TOS) {
                memcpy(&ecn, CMSG_DATA(cm), sizeof(ecn));
            }
        }

        ClientEndpoint ep;
        bool isv6;
        if (static_cast<sockaddr *>(drb.mhs[i].msg_hdr.msg_name)->sa_family == AF_INET6) {
            ep = *static_cast<sockaddr_in6 *>(drb.mhs[i].msg_hdr.msg_name);
            isv6 = true;
        } else {
            ep = *static_cast<sockaddr_in *>(drb.mhs[i].msg_hdr.msg_name);
            isv6 = false;
        }

        PacketBatch pb{
            .prefix = {},
            .data = {drb.bufs[i].data(), drb.mhs[i].msg_len},
            .segment_size = gro_size,
            .isv6 = isv6,
            .ecn = ecn,
        };
        drb.pbeps.emplace_back(pb, ep);
    }

    return nvecs;
}

} // namespace wireglider
