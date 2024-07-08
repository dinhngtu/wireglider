#include <sys/types.h>
#include <csignal>

#include "worker.hpp"
#include "ancillary.hpp"

using namespace wireglider::worker_impl;

namespace wireglider {

void Worker::do_server(epoll_event *ev) {
    if (ev->events & (EPOLLHUP | EPOLLERR)) {
        throw std::system_error(EIO, std::system_category(), "do_server events");
    }
    if (ev->events & EPOLLOUT)
        do_server_send();
    if (ev->events & EPOLLIN) {
        auto crypt = do_server_recv(ev, _recvbuf);
        if (!crypt)
            return;

        if constexpr (false) {
            auto batch = do_server_decap(crypt->first, crypt->second, _pktbuf);
            if (!batch)
                return;

            auto sendlist = new ServerSendList(std::move(batch->retpkt), crypt->second);
            auto ret = server_send_list(sendlist);
            if (ret) {
                assert(sendlist->pos == sendlist->mh.size());
                delete sendlist;
            } else {
                _serversend.push_back(*sendlist);
                server_enable(EPOLLOUT);
            }

            if (!do_tun_write_batch(*batch))
                return;

        } else {
            auto batch = do_server_decap_ref(crypt->first, crypt->second, _pktbuf);
            if (!batch)
                return;

            auto ret = server_send_reflist(batch->retpkt, crypt->second);
            if (ret.has_value()) {
                auto tosend = new ServerSendList(crypt->second);
                for (auto &iov : ret.value())
                    tosend->push_back(iov);
                tosend->finalize();
                _serversend.push_back(*tosend);
                server_enable(EPOLLOUT);
            }

            if (!do_tun_write_batch(*batch))
                return;
        }
    }
}

std::optional<std::pair<PacketBatch, ClientEndpoint>> Worker::do_server_recv(
    [[maybe_unused]] epoll_event *ev,
    std::vector<uint8_t> &buf) {
    if (buf.size() < 65536)
        buf.resize(65536);

    msghdr mh;
    memset(&mh, 0, sizeof(mh));

    std::array<uint8_t, sizeof(sockaddr_in6)> _name;
    mh.msg_name = _name.data();
    mh.msg_namelen = _name.size();
    iovec iov{buf.data(), buf.size()};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    AncillaryData<uint16_t, uint8_t> _cm(mh);

    auto bytes = recvmsg(_arg.server->fd(), &mh, 0);
    if (bytes < 0) {
        if (is_eagain())
            return std::nullopt;
        else
            throw std::system_error(errno, std::system_category(), "do_server_recv recvmsg");
    }

    size_t gro_size = static_cast<size_t>(bytes);
    uint8_t ecn = 0;
    for (auto cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
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
    if (static_cast<sockaddr *>(mh.msg_name)->sa_family == AF_INET6) {
        ep = *static_cast<sockaddr_in6 *>(mh.msg_name);
        isv6 = true;
    } else {
        ep = *static_cast<sockaddr_in *>(mh.msg_name);
        isv6 = false;
    }

    PacketBatch pb{
        .prefix = {},
        .data = {buf.data(), static_cast<size_t>(bytes)},
        .segment_size = gro_size,
        .isv6 = isv6,
        .ecn = ecn,
    };
    return std::make_pair(pb, ep);
}

} // namespace wireglider
