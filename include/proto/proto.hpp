#pragma once

#include <array>
#include <span>
#include <variant>
#include <noise/protocol.h>
#include <sodium.h>
#include <wireguard_ffi.h>
#include <tdutil/auto_handle.hpp>

#include "result.hpp"
#include "tai64n.hpp"
#include "disposable.hpp"

namespace wireglider::proto {

struct NoiseErrorCategory : public std::error_category {
    const char *name() const noexcept override {
        return "NoiseError";
    }

    std::string message(int cond) const override;
};

static inline NoiseErrorCategory noise_category() {
    return NoiseErrorCategory{};
}

struct [[gnu::packed]] Handshake1 {
    boost::endian::little_uint32_t message_type_and_zeroes;
    boost::endian::little_uint32_t sender_index;
    uint8_t handshake[32 + 32 + 16 + 12 + 16];
    uint8_t mac1[16];
    uint8_t mac2[16];
};

struct [[gnu::packed]] Handshake2 {
    boost::endian::little_uint32_t message_type_and_zeroes;
    boost::endian::little_uint32_t sender_index;
    boost::endian::little_uint32_t receiver_index;
    uint8_t handshake[32 + 0 + 16];
    uint8_t mac1[16];
    uint8_t mac2[16];
};

using Handshake = tdutil::auto_handle<noise_handshakestate_free>;
using Hash = tdutil::auto_handle<noise_hashstate_free>;

struct ProtoState {
    ProtoState() {
    }
    DISPOSABLE_COPYABLE(ProtoState);

    Handshake handshake;
    std::array<uint8_t, 64> cookie = {0};
    timespec cookie_until = time::timespec_min();

    struct {
        int role = 0;
        uint32_t remote_index = 0;
    } responder;

    DEFAULT_SWAP(ProtoState, handshake, cookie, cookie_until, responder.role, responder.remote_index);

private:
    void dispose() noexcept {
        handshake.reset();
        sodium_memzero(cookie.data(), cookie.size());
        cookie_until = timespec_min();
    }
};

struct HalfSessionState {
    int role = 0;
    uint32_t remote_index = 0;
};

struct SessionState {
    SessionState() {
    }
    DISPOSABLE_COPYABLE(SessionState);

    int role = 0;
    uint32_t remote_index = 0;
    std::array<uint8_t, 32> key1 = {0}, key2 = {0};
    timespec key_until = timespec_min();

    constexpr DEFAULT_SWAP(SessionState, role, remote_index, key1, key2, key_until);

private:
    void dispose() noexcept {
        role = 0;
        sodium_memzero(key1.data(), key1.size());
        sodium_memzero(key2.data(), key2.size());
        key_until = timespec_min();
    }
};

class Peer {
public:
    Peer(uint32_t index);
    constexpr Peer(const Peer &) = delete;
    constexpr Peer &operator=(const Peer &) = delete;
    Peer(Peer &&other) = delete;
    Peer &operator=(Peer &&other) = delete;

    void reset_handshake();
    void reset_all() {
        reset_handshake();
        _session = SessionState();
    }

    outcome::result<Handshake1 *> write_handshake1(timespec now, const x25519_key &pubkey, std::span<uint8_t> out);
    static outcome::result<const Handshake2 *> decode_handshake2(std::span<const uint8_t> in);
    outcome::result<void> read_handshake2(const Handshake2 *hs2, timespec now, const x25519_key &pubkey);

    static outcome::result<const Handshake1 *> decode_handshake1(std::span<const uint8_t> in);
    outcome::result<void> read_handshake1(const Handshake1 *hs1, timespec now, const x25519_key &pubkey);
    outcome::result<std::span<uint8_t>> write_handshake2(
        timespec now,
        const x25519_key &pubkey,
        std::span<uint8_t> out);

    std::span<const uint8_t> current_decryption_key(const timespec &now) const {
        using wireglider::time::operator<=>;
        auto pending = std::get_if<SessionState>(&_pending);
        if (pending && now < pending->key_until)
            return pending->key2;
        else if (now < _session.key_until)
            return _session.key2;
        else
            return {};
    }

    std::span<const uint8_t> current_encryption_key(const timespec &now) const {
        using wireglider::time::operator<=>;
        if (now < _session.key_until)
            return _session.key1;
        else
            return {};
    }

private:
    static outcome::result<NoiseProtocolId> make_proto_id();
    static outcome::result<Handshake> create_handshake(
        const NoiseProtocolId &nid,
        const x25519_key &server_privkey,
        const x25519_key *pubkey,
        std::span<const uint8_t, 32> psk,
        int role);
    outcome::result<void> configure_initiator(
        const x25519_key &server_privkey,
        const x25519_key &pubkey,
        std::span<const uint8_t, 32> psk);
    outcome::result<void> configure_responder(const x25519_key &server_privkey, std::span<const uint8_t, 32> psk);
    static outcome::result<void> write_handshake_raw(NoiseHandshakeState *hs, NoiseBuffer *out);
    static outcome::result<void> write_handshake_raw(NoiseHandshakeState *hs, time::TAI64N now, NoiseBuffer *out);
    static outcome::result<void> read_handshake_raw(NoiseHandshakeState *hs, NoiseBuffer *in, NoiseBuffer *out);
    outcome::result<void> make_mac1key(const x25519_key &pubkey, std::array<uint8_t, 64> &out);
    outcome::result<void> calculate_mac1(
        const x25519_key &pubkey,
        std::span<const uint8_t> payload,
        std::span<uint8_t, 16> out);

private:
    // configuration
    NoiseProtocolId _nid;
    Hash _blake2s;
    uint32_t _local_index = 0;

    // sticky state
    time::TAI64N _last_tm;

    ProtoState _proto;
    std::variant<std::monostate, HalfSessionState, SessionState> _pending;
    SessionState _session;

    tdutil::auto_cleanup _zeroize = tdutil::auto_cleanup([this] { reset_all(); });
};

} // namespace wireglider::proto
