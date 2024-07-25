#include <sys/types.h>
#include <csignal>

#include "worker.hpp"
#include "ancillary.hpp"

using namespace wireglider::worker_impl;

namespace wireglider {

static void tunnel_flush(
    [[maybe_unused]] RundownGuard &rcu,
    [[maybe_unused]] std::lock_guard<std::mutex> &lock,
    std::deque<std::vector<uint8_t>> &serversend,
    wireguard_tunnel_raw *tunnel,
    std::vector<uint8_t> &scratch) {
    while (1) {
        auto result = wireguard_read_raw(tunnel, nullptr, 0, scratch.data(), scratch.size());
        switch (result.op) {
        case WRITE_TO_NETWORK:
            serversend.emplace_back(&scratch[0], &scratch[result.size]);
            break;
        case WIREGUARD_DONE:
            return;
        case WIREGUARD_ERROR:
        default:
            return;
        }
    }
}

/*
 * packets sent from ep are decapsulated
 * each packet is a separate ip packet with:
 *  - src ip/port (sender side)
 *  - dst ip/port (may be client or tun destination elsewhere)
 *  - tcp/udp
 * see struct FlowKey for flow key description
 */
std::optional<DecapBatch> Worker::do_server_decap(PacketBatch pb, ClientEndpoint ep, std::vector<uint8_t> &scratch) {
    RundownGuard rcu;
    auto it = _arg.client_eps->find(rcu, ep);
    if (it == _arg.client_eps->end())
        return std::nullopt;

    DecapBatch batch(_arg.tun_has_uso);
    {
        auto state = it->state.synchronize();
        // TODO
        for (auto pkt : pb) {
            auto result = wireguard_read_raw(it->tunnel, pkt.data(), pkt.size(), scratch.data(), scratch.size());
            switch (result.op) {
            case WRITE_TO_TUNNEL_IPV4: {
                auto outpkt = std::span(&scratch[0], &scratch[result.size]);
                batch.push_packet_v4(outpkt, pb.ecn);
                break;
            }
            case WRITE_TO_TUNNEL_IPV6: {
                auto outpkt = std::span(&scratch[0], &scratch[result.size]);
                batch.push_packet_v6(outpkt, pb.ecn);
                break;
            }
            case WRITE_TO_NETWORK: {
                batch.retpkt.emplace_back(&scratch[0], &scratch[result.size]);
                tunnel_flush(rcu, client_lock, batch.retpkt, it->tunnel, scratch);
                break;
            }
            case WIREGUARD_ERROR:
            case WIREGUARD_DONE:
                break;
            }
        }
    }

    batch.aggregate_udp();
    return batch;
}

} // namespace wireglider
