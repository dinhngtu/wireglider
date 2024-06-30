#include <boost/endian.hpp>
#include <tdutil/util.hpp>
#include <fmt/format.h>

#include "worker.hpp"
#include "ancillary.hpp"

using namespace boost::endian;
using namespace wgss::worker_impl;

namespace wgss {

void Worker::do_server_send() {
    while (!_serversend.empty()) {
        auto ret = do_server_send_step(&_serversend.front());
        if (is_eagain(-ret)) {
            break;
        } else {
            if (ret < 0)
                fmt::print("do_server_send: {}\n", strerrordesc_np(ret));
            _serversend.pop_front_and_dispose(ServerSendBase::deleter());
        }
    }
    if (_serversend.empty())
        server_disable(EPOLLOUT);
    else if (_serversend.size() < 64)
        tun_enable(EPOLLIN);
    else
        tun_disable(EPOLLIN);
}

int Worker::server_send_batch(ServerSendBatch *batch, std::span<uint8_t> data, bool queue_on_eagain) {
    msghdr mh;
    memset(&mh, 0, sizeof(mh));
    if (auto sin6 = std::get_if<sockaddr_in6>(&batch->ep)) {
        mh.msg_name = sin6;
        mh.msg_namelen = sizeof(sockaddr_in6);
    } else if (auto sin = std::get_if<sockaddr_in>(&batch->ep)) {
        mh.msg_name = sin;
        mh.msg_namelen = sizeof(sockaddr_in);
    }
    mh.msg_iovlen = 1;

    AncillaryData<uint16_t, uint8_t> cm;
    cm.set(mh);
    cm.setmsg<0>(SOL_UDP, UDP_SEGMENT, batch->segment_size);
    // batch->ecn is set all the way from do_tun_gso_split()
    // it only contains the lower ECN bits and not DSCP per WG spec
    cm.setmsg<1>(SOL_IP, IP_TOS, batch->ecn);

    while (!data.empty()) {
        iovec iov{data.data(), data.size()};
        mh.msg_iov = &iov;
        auto ret = sendmsg(_arg.server->fd(), &mh, 0);
        if (ret < 0) {
            auto err = errno;
            if (queue_on_eagain && is_eagain()) {
                auto tosend = new ServerSendBatch(data, batch->segment_size, batch->ep);
                _serversend.push_back(*tosend);
                server_enable(EPOLLOUT);
            }
            return -err;
        } else {
            data = data.subspan(ret);
        }
    }

    return 0;
}

ServerSendList::ServerSendList(ServerSendList::packet_list &&pkts, ClientEndpoint _ep)
    : packets(std::move(pkts)), ep(_ep), pos(0) {
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

    iovecs.reserve(packets.size());
    mh.reserve(packets.size());
    for (auto it = packets.begin(); it != packets.end(); it++)
        iovecs.push_back(iovec{it->data(), it->size()});
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

int Worker::server_send_list(ServerSendList *list) {
    while (list->pos < list->mh.size()) {
        auto ret = sendmmsg(_arg.server->fd(), &list->mh[list->pos], list->mh.size() - list->pos, 0);
        if (ret < 0)
            return -errno;
        else
            list->pos += ret;
    }
    return 0;
}

int Worker::do_server_send_step(ServerSendBase *send) {
    if (typeid(*send) == typeid(ServerSendBatch)) {
        auto batch = static_cast<ServerSendBatch *>(send);
        auto ret = server_send_batch(batch);
        // TODO: update send position for this batch
        return ret;
    } else if (typeid(*send) == typeid(ServerSendList)) {
        auto list = static_cast<ServerSendList *>(send);
        return server_send_list(list);
    } else {
        tdutil::unreachable();
    }
}

} // namespace wgss
