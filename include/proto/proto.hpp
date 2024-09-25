#pragma once

#include <array>
#include <cstdint>
#include <sodium/utils.h>
#include <span>
#include <type_traits>
#include <variant>
#include <noise/protocol.h>
#include <sodium.h>
#include <tdutil/auto_handle.hpp>
#include <tdutil/time.hpp>
#include <tdutil/util.hpp>

#include "keys.hpp"
#include "result.hpp" // IWYU pragma: keep
#include "tai64n.hpp"
#include "replay.hpp"
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

static const uint64_t RekeyAfterMessages = 1ull << 60;
static const uint64_t RejectAfterMessages = UINT64_MAX - (1ull << 13);
static const long OneSecond = 1'000'000'000l;
static const long OneMillisecond = 1'000'000l;
static const long RekeyAfterTime = OneSecond * 120;
static const long RekeyAttemptTime = OneSecond * 90;
static const long RekeyTimeout = OneSecond * 5;
static const long MaxTimerHandshakes = 90 / 5;
static const long RekeyTimeoutJitterMaxMs = 333;
static const long RejectAfterTime = OneSecond * 180;
static const long KeepaliveTimeout = OneSecond * 10;
static const long CookieRefreshTime = OneSecond * 120;
static const long HandshakeInitationRate = OneSecond / 50;
static const uint64_t PaddingMultiple = 16;

// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays)

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

struct [[gnu::packed]] CookiePacket {
    boost::endian::little_uint32_t message_type_and_zeroes;
    boost::endian::little_uint32_t receiver_index;
    uint8_t nonce[24];
    uint8_t encrypted_cookie[16 + 16];
};

struct [[gnu::packed]] DataHeader {
    boost::endian::little_uint32_t message_type_and_zeroes;
    boost::endian::little_uint32_t receiver_index;
    boost::endian::little_uint64_t counter;
};

// NOLINTEND(cppcoreguidelines-avoid-c-arrays)

using Handshake = tdutil::auto_handle<noise_handshakestate_free>;
using Hash = tdutil::auto_handle<noise_hashstate_free>;

struct ProtoState {
    ProtoState() {
    }
    DISPOSABLE(ProtoState);

    Handshake handshake;
    timespec handshake_begin = time::timespec_min();
    std::array<uint8_t, 64> cookie = {0};
    timespec cookie_until = time::timespec_min();

    bool exists() const {
        return !!handshake;
    }

    bool is_role(int role) const {
        return handshake && noise_handshakestate_get_role(handshake.get()) == role;
    }

    bool is_action(int action) const {
        return handshake && noise_handshakestate_get_action(handshake.get()) == action;
    }

    DEFAULT_SWAP(ProtoState, handshake, cookie, cookie_until);

private:
    DEFAULT_DISPOSE(ProtoState, handshake, cookie, cookie_until);
};

struct HalfSessionState {
    int role = 0;
    uint32_t remote_index = 0;
};

struct SessionState {
    SessionState() {
    }
    SessionState(
        int _role,
        uint32_t rid,
        const uint8_t *_key1,
        size_t len1,
        const uint8_t *_key2,
        size_t len2,
        const timespec &_birth)
        : role(_role), remote_index(rid), birth(_birth), last_send(_birth), last_recv(_birth),
          replay(RejectAfterMessages) {
        std::copy(_key1, _key1 + len1, key1.begin());
        std::copy(_key2, _key2 + len2, key2.begin());
    }
    DISPOSABLE(SessionState);

    int role = 0;
    uint32_t remote_index = 0;
    std::array<uint8_t, 32> key1 = {0}, key2 = {0};
    timespec birth = time::timespec_min();
    timespec last_send = time::timespec_min(), last_recv = time::timespec_min();
    uint64_t encrypt_nonce = 0;
    ReplayRing<uint64_t, 8192> replay = ReplayRing<uint64_t, 8192>(RejectAfterMessages);

    bool exists() const {
        return !!role;
    }
    bool expired(const timespec &now, long life = RejectAfterTime) const {
        using tdutil::operators::operator-;
        return !exists() || (now - birth) > life;
    }

    void reset() {
        dispose();
    }

    DEFAULT_SWAP(SessionState, role, remote_index, key1, key2, birth, encrypt_nonce, replay);

private:
    void dispose() noexcept {
        role = 0;
        remote_index = 0;
        sodium_memzero(key1.data(), key1.size());
        sodium_memzero(key2.data(), key2.size());
        birth = time::timespec_min();
        encrypt_nonce = 0;
        replay.reset();
    }
};

enum class DecryptError {
    Rejected,
    NoSession,
};

enum class ProtoSignal {
    Ok = 0,
    OldSession = 1,
    NeedsHandshake = 2,
    NeedsKeepalive = 4,
    // Encryption key has been wiped. Protocol is in uninitialized state.
    SessionWasReset = 8,
    // Handshake attempts have failed. Any queued packets need to be removed.
    NeedsQueueClear = 16,
};

static inline bool operator!(ProtoSignal a) {
    return !static_cast<std::underlying_type_t<ProtoSignal>>(a);
}

static inline ProtoSignal operator&(ProtoSignal a, ProtoSignal b) {
    return static_cast<ProtoSignal>(
        static_cast<std::underlying_type_t<ProtoSignal>>(a) & static_cast<std::underlying_type_t<ProtoSignal>>(b));
}
static inline ProtoSignal operator|(ProtoSignal a, ProtoSignal b) {
    return static_cast<ProtoSignal>(
        static_cast<std::underlying_type_t<ProtoSignal>>(a) | static_cast<std::underlying_type_t<ProtoSignal>>(b));
}
static inline ProtoSignal &operator&=(ProtoSignal &a, ProtoSignal b) {
    a = a & b;
    return a;
}
static inline ProtoSignal &operator|=(ProtoSignal &a, ProtoSignal b) {
    a = a | b;
    return a;
}

struct ProtoSuccess {
    unsigned long long outsize;
    ProtoSignal signal;
};

enum class EncryptError {
    NoSession,
    BufferError,
};

using EncryptResult = outcome::result<ProtoSuccess, EncryptError>;
using DecryptResult = outcome::result<ProtoSuccess, DecryptError>;

class Peer {
public:
    Peer(uint32_t index);
    constexpr Peer(const Peer &) = delete;
    constexpr Peer &operator=(const Peer &) = delete;
    Peer(Peer &&other) = delete;
    Peer &operator=(Peer &&other) = delete;
    ~Peer() {
    }

    outcome::result<void> configure_initiator(
        const timespec &now,
        const Key256 &server_privkey,
        const Key256 &pubkey,
        std::span<const uint8_t, 32> psk);
    outcome::result<void> configure_responder(
        const timespec &now,
        const Key256 &server_privkey,
        std::span<const uint8_t, 32> psk);

    std::variant<std::monostate, const Handshake1 *, const Handshake2 *, const CookiePacket *, std::span<const uint8_t>>
    decode_pkt(std::span<const uint8_t> in);

    outcome::result<Handshake1 *> write_handshake1(const timespec &now, const Key256 &pubkey, std::span<uint8_t> out);
    outcome::result<void> read_handshake2(const Handshake2 *hs2, const timespec &now);
    outcome::result<void> read_handshake1(const Handshake1 *hs1);
    outcome::result<std::span<uint8_t>> write_handshake2(
        const timespec &now,
        const Key256 &pubkey,
        std::span<uint8_t> out);

    DecryptResult decrypt(const timespec &now, std::span<uint8_t> out, std::span<const uint8_t> in);
    EncryptResult encrypt(const timespec &now, std::span<uint8_t> out, std::span<const uint8_t> in);
    ProtoSignal tick(const timespec &now);

    uint64_t increment() {
        return _session.encrypt_nonce++;
    }

    static constexpr size_t expected_encrypt_size(size_t ptext_size) {
        auto padded_size = tdutil::round_up(ptext_size, 16);
        return sizeof(DataHeader) + padded_size + crypto_aead_chacha20poly1305_IETF_ABYTES;
    }

    static constexpr size_t expected_encrypt_overhead(size_t ptext_size) {
        auto padded_size = tdutil::round_up(ptext_size, 16);
        return sizeof(DataHeader) + padded_size - ptext_size + crypto_aead_chacha20poly1305_IETF_ABYTES;
    }

private:
    // Reset handshake state and set handshake birth time.
    void reset_handshake(const timespec &now);
    // Reset handshake and active session.
    void reset_all(const timespec &now) {
        reset_handshake(now);
        _session.reset();
    }

    static outcome::result<NoiseProtocolId> make_proto_id();
    static outcome::result<Handshake> create_handshake(
        const NoiseProtocolId &nid,
        const Key256 &server_privkey,
        const Key256 *pubkey,
        std::span<const uint8_t, 32> psk,
        int role);
    static outcome::result<void> write_handshake_raw(NoiseHandshakeState *hs, NoiseBuffer *out);
    static outcome::result<void> write_handshake_raw(NoiseHandshakeState *hs, time::TAI64N now, NoiseBuffer *out);
    static outcome::result<void> read_handshake_raw(NoiseHandshakeState *hs, NoiseBuffer *in, NoiseBuffer *out);

    Key256 get_my_pubkey();
    void make_mac1key(const Key256 &pubkey, std::span<uint8_t, 32> out);
    outcome::result<void> calculate_mac1(
        const Key256 &pubkey,
        std::span<const uint8_t> payload,
        std::span<uint8_t, 16> out);

private:
    // configuration
    NoiseProtocolId _nid;
    uint32_t _local_index = 0;

    // sticky states
    // last handshake timestamp of remote initiator (DoS mitigation)
    time::TAI64N _last_remote_hs1;
    timespec _next_hs1_retry = time::timespec_min();

    ProtoState _proto;
    std::variant<std::monostate, HalfSessionState, SessionState> _pending;
    SessionState _session;

    tdutil::auto_cleanup _zeroize = tdutil::auto_cleanup([this] { reset_all(time::timespec_min()); });
};

} // namespace wireglider::proto
