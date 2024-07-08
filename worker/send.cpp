#include <boost/endian.hpp>
#include <tdutil/util.hpp>

#include "worker.hpp"
#include "ancillary.hpp"

using namespace boost::endian;
using namespace wireglider::worker_impl;

namespace wireglider {

void Worker::do_server_send() {
    while (!_serversend.empty()) {
        auto ret = do_server_send_step(&_serversend.front());
        if (ret)
            _serversend.pop_front_and_dispose(ServerSendBase::deleter{});
        else
            break;
    }
    if (_serversend.empty())
        server_disable(EPOLLOUT);
    else if (_serversend.size() < 64)
        tun_enable(EPOLLIN);
    else
        tun_disable(EPOLLIN);
}

outcome::result<void> Worker::server_send_batch(ServerSendBatch *batch, std::span<uint8_t> data) {
    msghdr mh;
    memset(&mh, 0, sizeof(mh));
    if (auto sin6 = std::get_if<sockaddr_in6>(&batch->ep)) {
        mh.msg_name = sin6;
        mh.msg_namelen = sizeof(sockaddr_in6);
    } else if (auto sin = std::get_if<sockaddr_in>(&batch->ep)) {
        mh.msg_name = sin;
        mh.msg_namelen = sizeof(sockaddr_in);
    }
    iovec iov{};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;

    AncillaryData<uint16_t, uint8_t> cm(mh);
    cm.set<0>(SOL_UDP, UDP_SEGMENT, batch->segment_size);
    // batch->ecn is set all the way from do_tun_gso_split()
    // it only contains the lower ECN bits and not DSCP per WG spec
    cm.set<1>(SOL_IP, IP_TOS, batch->ecn);

    while (batch->pos < data.size()) {
        iov = {&data[batch->pos], std::min(batch->max_send, data.size() - batch->pos)};
        auto ret = sendmsg(_arg.server->fd(), &mh, 0);
        if (ret < 0)
            return check_eagain(errno, "server_send_batch sendmsg");
        else
            batch->pos += ret;
    }
    return outcome::success();
}

ServerSendList::ServerSendList(ServerSendList::packet_list &&pkts, ClientEndpoint _ep)
    : packets(std::move(pkts)), ep(_ep) {
    iovecs.reserve(packets.size());
    mh.reserve(packets.size());
    for (auto it = packets.begin(); it != packets.end(); it++)
        iovecs.push_back(iovec{it->data(), it->size()});
    finalize();
}

void ServerSendList::push_back(iovec pkt) {
    auto base = static_cast<const uint8_t *>(pkt.iov_base);
    packets.emplace_back(base, base + pkt.iov_len);
    iovecs.push_back({packets.back().data(), packets.back().size()});
}

void ServerSendList::finalize() {
    void *name = nullptr;
    socklen_t namelen;
    if (auto sin6 = std::get_if<sockaddr_in6>(&ep)) {
        name = sin6;
        namelen = sizeof(sockaddr_in6);
    } else if (auto sin = std::get_if<sockaddr_in>(&ep)) {
        name = sin;
        namelen = sizeof(sockaddr_in);
    } else {
        tdutil::unreachable();
    }

    mh.reserve(packets.size());
    for (auto &iov : iovecs)
        mh.push_back(mmsghdr{
            msghdr{
                .msg_name = name,
                .msg_namelen = namelen,
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = nullptr,
                .msg_controllen = 0,
                .msg_flags = 0,
            },
            0,
        });
}

outcome::result<void> Worker::server_send_list(ServerSendList *list) {
    while (list->pos < list->mh.size()) {
        auto ret = sendmmsg(_arg.server->fd(), &list->mh[list->pos], list->mh.size() - list->pos, 0);
        if (ret < 0)
            return check_eagain(errno, "server_send_list sendmmsg");
        else
            list->pos += ret;
    }
    return outcome::success();
}

std::optional<std::span<const iovec>> Worker::server_send_reflist(
    const boost::container::small_vector_base<iovec> &pkts,
    ClientEndpoint ep) {
    void *name = nullptr;
    socklen_t namelen;
    if (auto sin6 = std::get_if<sockaddr_in6>(&ep)) {
        name = sin6;
        namelen = sizeof(sockaddr_in6);
    } else if (auto sin = std::get_if<sockaddr_in>(&ep)) {
        name = sin;
        namelen = sizeof(sockaddr_in);
    } else {
        tdutil::unreachable();
    }
    std::vector<mmsghdr> mh;
    mh.reserve(pkts.size());
    std::span<const iovec> rest(pkts);
    while (!rest.empty()) {
        mh.clear();
        for (auto it = rest.begin(); it != rest.end(); it++) {
            mh.push_back({
                msghdr{
                    .msg_name = name,
                    .msg_namelen = namelen,
                    .msg_iov = const_cast<iovec *>(&*it),
                    .msg_iovlen = 1,
                    .msg_control = nullptr,
                    .msg_controllen = 0,
                    .msg_flags = 0,
                },
                0,
            });
        }
        auto ret = sendmmsg(_arg.server->fd(), mh.data(), mh.size(), 0);
        if (ret < 0) {
            if (is_eagain())
                return rest;
            else
                throw std::system_error(errno, std::system_category(), "server_send_reflist sendmsg");
        }
        rest = rest.subspan(ret);
    }
    return std::nullopt;
}

outcome::result<void> Worker::do_server_send_step(ServerSendBase *send) {
    if (typeid(*send) == typeid(ServerSendBatch)) {
        auto batch = static_cast<ServerSendBatch *>(send);
        return server_send_batch(batch, batch->buf);
    } else if (typeid(*send) == typeid(ServerSendList)) {
        auto list = static_cast<ServerSendList *>(send);
        return server_send_list(list);
    } else {
        tdutil::unreachable();
    }
}

} // namespace wireglider
