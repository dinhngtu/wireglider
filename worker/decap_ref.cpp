#include <sys/types.h>
#include <csignal>

#include "worker.hpp"
#include "ancillary.hpp"

using namespace wireglider::worker_impl;

namespace wireglider {

// TODO
static std::span<uint8_t> tunnel_flush(
    [[maybe_unused]] RundownGuard &rcu,
    [[maybe_unused]] std::lock_guard<std::mutex> &lock,
    boost::container::small_vector_base<iovec> &serversend,
    wireguard_tunnel_raw *tunnel,
    std::span<uint8_t> scratch) {
    auto rest = scratch;
    while (1) {
        auto result = wireguard_read_raw(tunnel, nullptr, 0, rest.data(), rest.size());
        switch (result.op) {
        case WRITE_TO_NETWORK:
            serversend.emplace_back(&rest[0], &rest[result.size]);
            rest = rest.subspan(result.size);
            break;
        case WIREGUARD_DONE:
            break;
        case WIREGUARD_ERROR:
        // TODO
        default:
            break;
        }
    }
    return rest;
}

std::optional<DecapRefBatch> Worker::do_server_decap_ref(
    PacketBatch pb,
    ClientEndpoint ep,
    std::vector<uint8_t> &_scratch) {
    RundownGuard rcu;
    auto it = _arg.client_eps->find(rcu, ep);
    if (it == _arg.client_eps->end())
        return std::nullopt;

    DecapRefBatch batch;
    {
        std::lock_guard client_lock(it->mutex);
        auto rest = pb.data;
        std::span rest(_scratch);
        for (auto pkt : pb) {
            auto result = wireguard_read_raw(it->tunnel, pkt.data(), pkt.size(), rest.data(), rest.size());
            switch (result.op) {
            case WRITE_TO_TUNNEL_IPV4: {
                auto outpkt = rest.subspan(0, result.size);
                rest = rest.subspan(result.size);
                batch.push_packet_v4(outpkt, pb.ecn);
                break;
            }
            case WRITE_TO_TUNNEL_IPV6: {
                auto outpkt = rest.subspan(0, result.size);
                rest = rest.subspan(result.size);
                batch.push_packet_v6(outpkt, pb.ecn);
                break;
            }
            case WRITE_TO_NETWORK: {
                batch.retpkt.push_back({rest.data(), result.size});
                rest = rest.subspan(result.size);
                rest = tunnel_flush(rcu, client_lock, batch.retpkt, it->tunnel, rest);
                break;
            }
            case WIREGUARD_ERROR:
            // TODO
            case WIREGUARD_DONE:
                break;
            }
        }
    }

    batch.aggregate_udp();
    return batch;
}

} // namespace wireglider
