#pragma once

#include <memory>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <boost/container/deque.hpp>
#include <boost/container/small_vector.hpp>
#include <tdutil/util.hpp>

#include "checksum.hpp"
#include "endian.hpp"
#include "worker/flowkey.hpp"

using namespace boost::endian;

namespace wireglider::worker_impl {

struct PacketRefBatch {
    explicit PacketRefBatch() {
    }
    explicit PacketRefBatch(std::span<const uint8_t> hdr, const PacketFlags &_flags)
        : hdrbuf(hdr.begin(), hdr.end()), flags(_flags) {
    }
    PacketRefBatch(const PacketRefBatch &) = default;
    PacketRefBatch &operator=(const PacketRefBatch &) = default;
    PacketRefBatch(PacketRefBatch &&other) noexcept
        : hdrbuf(std::move(other.hdrbuf)), iov(std::move(other.iov)), bytes(std::exchange(other.bytes, 0)),
          flags(other.flags) {
        bytes = std::exchange(other.bytes, 0);
    }
    PacketRefBatch &operator=(PacketRefBatch &&other) noexcept {
        if (this != &other) {
            hdrbuf = std::move(other.hdrbuf);
            iov = std::move(other.iov);
            bytes = std::exchange(other.bytes, 0);
            flags = other.flags;
        }
        return *this;
    }
    ~PacketRefBatch() = default;

    size_t size_bytes() const {
        return bytes;
    }
    void append(std::span<const uint8_t> data) {
        if (!iov.empty() && data.data() == static_cast<uint8_t *>(iov.back().iov_base) + iov.back().iov_len)
            iov.back().iov_len += data.size();
        else
            iov.push_back({const_cast<uint8_t *>(data.data()), data.size()});
        bytes += data.size();
    }
    void extend(PacketRefBatch &other) {
        std::copy(other.iov.begin() + 2, other.iov.end(), std::back_inserter(iov));
        bytes += other.bytes;
        other.iov.clear();
        other.bytes = 0;
    }
    bool is_appendable(size_t size) const {
        return iov.size() + 1 < 64 && bytes + size < 65536;
    }
    bool is_mergeable(const PacketRefBatch &other) const {
        return iov.size() + other.iov.size() < 66 && bytes + other.bytes < 65536;
    }
    struct ip *ip4hdr() {
        assert(!flags.isv6());
        return reinterpret_cast<struct ip *>(hdrbuf.data());
    }
    struct ip6_hdr *ip6hdr() {
        assert(flags.isv6());
        return reinterpret_cast<struct ip6_hdr *>(hdrbuf.data());
    }
    struct tcphdr *tcphdr() {
        assert(flags.istcp());
        return reinterpret_cast<struct tcphdr *>(&hdrbuf[flags.vnethdr.csum_start]);
    }
    struct udphdr *udphdr() {
        assert(!flags.istcp());
        return reinterpret_cast<struct udphdr *>(&hdrbuf[flags.vnethdr.csum_start]);
    }
    void finalize() {
        iov[0] = {&flags.vnethdr, sizeof(flags.vnethdr)};
        iov[1] = {hdrbuf.data(), hdrbuf.size()};

        auto l4len = hdrbuf.size() - flags.vnethdr.csum_start + size_bytes();
        if (!flags.istcp())
            assign_big_from_native(udphdr()->len, l4len);

        unsigned int proto_off, srcaddr_off, dstaddr_off, addrsize;
        if (flags.isv6()) {
            proto_off = offsetof(ip6_hdr, ip6_nxt);
            srcaddr_off = offsetof(ip6_hdr, ip6_src);
            dstaddr_off = offsetof(ip6_hdr, ip6_dst);
            addrsize = sizeof(in6_addr);

            assign_big_from_native(ip6hdr()->ip6_plen, l4len);
        } else {
            proto_off = offsetof(struct ip, ip_p);
            srcaddr_off = offsetof(struct ip, ip_src);
            dstaddr_off = offsetof(struct ip, ip_dst);
            addrsize = sizeof(in_addr);

            auto ip = ip4hdr();
            assign_big_from_native(ip->ip_len, hdrbuf.size() + size_bytes());
            ip->ip_sum = 0;
            // native order
            ip->ip_sum = checksum(std::span(hdrbuf.data(), flags.vnethdr.csum_start), 0);
        }
        auto l4_csum = pseudo_header_checksum(
            hdrbuf[proto_off],
            std::span(hdrbuf.data() + srcaddr_off, addrsize),
            std::span(hdrbuf.data() + dstaddr_off, addrsize),
            l4len);
        // native order
        memcpy(&hdrbuf[flags.vnethdr.csum_start + flags.vnethdr.csum_offset], &l4_csum, sizeof(l4_csum));
    }

    boost::container::small_vector<uint8_t, 64> hdrbuf;
    // the two first iovecs are reserved for vnethdr and hdrbuf
    boost::container::small_vector<iovec, 16> iov = boost::container::small_vector<iovec, 16>(2);
    size_t bytes = 0;
    PacketFlags flags;
};

template <typename AddressType>
using RefFlowMap = boost::container::
    small_flat_map<FlowKey<AddressType>, std::unique_ptr<PacketRefBatch>, 3, std::greater<FlowKey<AddressType>>>;
using IP4RefFlow = RefFlowMap<in_addr>;
using IP6RefFlow = RefFlowMap<in6_addr>;

struct DecapRefBatch {
    using unrel_type =
        boost::container::deque<iovec, void, boost::container::deque_options_t<boost::container::block_size<128u>>>;
    using retpkt_type = boost::container::small_vector<iovec, 8>;

    [[deprecated("must specify has_uso")]] DecapRefBatch() : has_uso(true) {
    }
    explicit DecapRefBatch(bool _has_uso) : has_uso(_has_uso) {
    }

    IP4RefFlow tcp4;
    IP4RefFlow udp4;
    IP6RefFlow tcp6;
    IP6RefFlow udp6;
    // packets that are not aggregated
    unrel_type unrel;

    // packets that must be returned to the client for protocol reasons
    retpkt_type retpkt;

    // unique udp flow number
    uint32_t udpid = 0;
    bool has_uso;

    DecapOutcome push_packet_v4(std::span<const uint8_t> ippkt, uint8_t ecn_outer);
    DecapOutcome push_packet_v6(std::span<const uint8_t> ippkt, uint8_t ecn_outer);
    DecapOutcome push_packet(std::span<const uint8_t> ippkt, uint8_t ecn_outer);
};

struct FlowkeyRefMeta {
    static constexpr size_t PacketRefBatchSize = sizeof(PacketRefBatch);
    static constexpr size_t IP4RefFlowSize = sizeof(IP4RefFlow);
    static constexpr size_t IP4FlowKeySize = sizeof(IP4RefFlow::key_type);
    static constexpr size_t IP4FlowValueSize = sizeof(IP4RefFlow::value_type);
    static constexpr size_t IP6RefFlowSize = sizeof(IP6RefFlow);
    static constexpr size_t IP6FlowKeySize = sizeof(IP6RefFlow::key_type);
    static constexpr size_t IP6FlowValueSize = sizeof(IP6RefFlow::value_type);
    static constexpr size_t DecapRefUnrelSize = sizeof(DecapRefBatch::unrel_type);
    static constexpr size_t DecapRefRetpktSize = sizeof(DecapRefBatch::retpkt_type);
    static constexpr size_t DecapRefBatchSize = sizeof(DecapRefBatch);
};

} // namespace wireglider::worker_impl
