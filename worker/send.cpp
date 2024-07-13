#include <boost/endian.hpp>
#include <tdutil/util.hpp>

#include "worker.hpp"
#include "ancillary.hpp"

using namespace boost::endian;
using namespace wireglider::worker_impl;

namespace wireglider {

void Worker::do_server_send() {
    while (!_serversend.empty()) {
        auto ret = _serversend.front().send(_arg.server->fd());
        if (ret)
            _serversend.pop_front_and_dispose(ServerSendBase::deleter{});
        else
            break;
    }
    if (_serversend.empty())
        server_disable(EPOLLOUT);
    if (_serversend.size() < 64)
        tun_enable(EPOLLIN);
    else
        tun_disable(EPOLLIN);
}

outcome::result<void> ServerSendBatch::send(int fd, std::span<uint8_t> data) {
    msghdr mh;
    memset(&mh, 0, sizeof(mh));
    if (auto sin6 = std::get_if<sockaddr_in6>(&ep)) {
        mh.msg_name = sin6;
        mh.msg_namelen = sizeof(sockaddr_in6);
    } else if (auto sin = std::get_if<sockaddr_in>(&ep)) {
        mh.msg_name = sin;
        mh.msg_namelen = sizeof(sockaddr_in);
    }
    iovec iov{};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;

    AncillaryData<uint16_t, uint8_t> cm(mh);
    cm.set<0>(SOL_UDP, UDP_SEGMENT, segment_size);
    // ecn is set all the way from do_tun_gso_split()
    // it only contains the lower ECN bits and not DSCP per WG spec
    cm.set<1>(SOL_IP, IP_TOS, ecn);

    while (pos < data.size()) {
        iov = {&data[pos], std::min(max_send, data.size() - pos)};
        auto ret = sendmsg(fd, &mh, 0);
        if (ret < 0)
            return check_eagain(errno, "ServerSendBatch sendmsg");
        else
            pos += ret;
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
    assert(!finalized);
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
    finalized = true;
}

outcome::result<void> ServerSendList::send(int fd) {
    if (!finalized)
        throw std::runtime_error("ServerSendList not finalized");
    while (pos < mh.size()) {
        auto ret = sendmmsg(fd, &mh[pos], mh.size() - pos, 0);
        if (ret < 0)
            return check_eagain(errno, "ServerSendList sendmmsg");
        else
            pos += ret;
    }
    return outcome::success();
}

std::optional<std::span<const iovec>> Worker::server_send_reflist(std::span<iovec> pkts, ClientEndpoint ep) {
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
        for (auto &iov : rest) {
            mh.push_back({
                msghdr{
                    .msg_name = name,
                    .msg_namelen = namelen,
                    .msg_iov = const_cast<iovec *>(&iov),
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

void ServerSendMultilist::push_back(iovec pkt, ClientEndpoint ep) {
    assert(!finalized);
    auto base = static_cast<const uint8_t *>(pkt.iov_base);
    packets.emplace_back(base, base + pkt.iov_len);
    iovecs.push_back({packets.back().data(), packets.back().size()});
    eps.push_back(ep);
}

void ServerSendMultilist::finalize() {
    mh.reserve(packets.size());
    for (size_t i = 0; i < packets.size(); i++) {
        void *sa;
        socklen_t sz;
        if (auto sin6 = std::get_if<sockaddr_in6>(&eps[i])) {
            sa = sin6;
            sz = sizeof(sockaddr_in6);
        } else if (auto sin = std::get_if<sockaddr_in>(&eps[i])) {
            sa = sin;
            sz = sizeof(sockaddr_in);
        } else {
            tdutil::unreachable();
        }
        mh.push_back(mmsghdr{
            msghdr{
                .msg_name = sa,
                .msg_namelen = sz,
                .msg_iov = &iovecs[i],
                .msg_iovlen = 1,
                .msg_control = nullptr,
                .msg_controllen = 0,
                .msg_flags = 0,
            },
            0,
        });
    }
    finalized = true;
}

outcome::result<void> ServerSendMultilist::send(int fd) {
    if (!finalized)
        throw std::runtime_error("ServerSendMultilist not finalized");
    while (pos < mh.size()) {
        auto ret = sendmmsg(fd, &mh[pos], mh.size() - pos, 0);
        if (ret < 0)
            return check_eagain(errno, "ServerSendMultilist sendmmsg");
        else
            pos += ret;
    }
    return outcome::success();
}

} // namespace wireglider
