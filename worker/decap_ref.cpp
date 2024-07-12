#include <sys/types.h>
#include <csignal>

#include "worker.hpp"
#include "ancillary.hpp"
#include "dbgprint.hpp"

using namespace wireglider::worker_impl;

namespace wireglider {

static std::span<uint8_t> tunnel_flush(
    [[maybe_unused]] RundownGuard &rcu,
    [[maybe_unused]] std::lock_guard<std::mutex> &lock,
    boost::container::small_vector_base<iovec> &serversend,
    wireguard_tunnel_raw *tunnel,
    std::span<uint8_t> scratch) {
    auto remain = scratch;
    while (1) {
        auto result = wireguard_read_raw(tunnel, nullptr, 0, remain.data(), remain.size());
        switch (result.op) {
        case WRITE_TO_NETWORK:
            DBG_PRINT("tunnel flush v4 {}\n", result.size);
            serversend.push_back({&remain[0], result.size});
            remain = remain.subspan(result.size);
            break;
        case WIREGUARD_DONE:
            return remain;
        case WIREGUARD_ERROR:
        default:
            DBG_PRINT("unexpected tunnel_flush result {}\n", static_cast<int>(result.op));
            return remain;
        }
    }
}

std::optional<DecapRefBatch> Worker::do_server_decap_ref(
    PacketBatch pb,
    ClientEndpoint ep,
    std::vector<uint8_t> &memory) {
    RundownGuard rcu;
    auto it = _arg.client_eps->find(rcu, ep);
    if (it == _arg.client_eps->end())
        return std::nullopt;

    DecapRefBatch batch(_arg.tun_has_uso);
    {
        std::lock_guard client_lock(it->mutex);
        std::span remain(memory);
        bool flush = true;
        for (auto pkt : pb) {
            auto result = wireguard_read_raw(it->tunnel, pkt.data(), pkt.size(), remain.data(), remain.size());
            switch (result.op) {
            case WRITE_TO_TUNNEL_IPV4: {
                // DBG_PRINT("tun write v4 {}\n", result.size);
                auto outpkt = remain.subspan(0, result.size);
                remain = remain.subspan(result.size);
                batch.push_packet_v4(outpkt, pb.ecn);
                break;
            }
            case WRITE_TO_TUNNEL_IPV6: {
                // DBG_PRINT("tun write v6 {}\n", result.size);
                auto outpkt = remain.subspan(0, result.size);
                remain = remain.subspan(result.size);
                batch.push_packet_v6(outpkt, pb.ecn);
                break;
            }
            case WRITE_TO_NETWORK: {
                DBG_PRINT("decap net write {}\n", result.size);
                batch.retpkt.push_back({remain.data(), result.size});
                remain = remain.subspan(result.size);
                flush = true;
                break;
            }
            case WIREGUARD_DONE:
                break;
            case WIREGUARD_ERROR:
            default:
                DBG_PRINT("unexpected decap result {}\n", static_cast<int>(result.op));
                break;
            }
        }
        if (flush)
            remain = tunnel_flush(rcu, client_lock, batch.retpkt, it->tunnel, remain);
    }

    return batch;
}

} // namespace wireglider
