#include <cstring>
#include <sodium.h>
#include <boost/endian.hpp>
#include <tdutil/time.hpp>
#include <tdutil/util.hpp>

#include "proto.hpp"

using namespace boost::endian;
using namespace tdutil;
using namespace wireglider::time;
using namespace tdutil::operators;

#define WIREGUARD_PROTO_NAME "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define WIREGUARD_IDENTIFIER "WireGuard v1 zx2c4 Jason@zx2c4.com"
#define WIREGUARD_LABEL_MAC1 "mac1----"

const char *noise_errstr(int err);

static constexpr NoiseBuffer noise_input(std::span<const uint8_t> span) {
    NoiseBuffer ret;
    noise_buffer_set_input(ret, const_cast<uint8_t *>(span.data()), span.size());
    return ret;
}

static constexpr NoiseBuffer noise_output(std::span<uint8_t> span) {
    NoiseBuffer ret;
    noise_buffer_set_output(ret, span.data(), span.size());
    return ret;
}

static constexpr NoiseBuffer noise_inout(std::span<uint8_t> span, size_t datasize) {
    NoiseBuffer ret;
    noise_buffer_set_inout(ret, span.data(), datasize, span.size());
    return ret;
}

namespace wireglider::proto {

enum MessageType : uint32_t {
    First = 1,
    Second = 2,
    Cookie = 3,
    Data = 4,
};

std::string NoiseErrorCategory::message(int cond) const {
    return noise_errstr(cond);
}

Peer::Peer(uint32_t index) : _nid(make_proto_id().value()), _local_index(index) {
    NoiseHashState *hash;
    auto err = noise_hashstate_new_by_id(&hash, NOISE_HASH_BLAKE2s);
    if (err != NOISE_ERROR_NONE)
        throw std::system_error(err, noise_category(), "noise_hashstate_new_by_id");
    _blake2s = Hash(hash);
}

outcome::result<NoiseProtocolId> Peer::make_proto_id() {
    NoiseProtocolId nid{};
    auto err = noise_protocol_name_to_id(&nid, WIREGUARD_PROTO_NAME, strlen(WIREGUARD_PROTO_NAME));
    if (err == NOISE_ERROR_NONE)
        return nid;
    else
        return std::error_code(err, noise_category());
}

outcome::result<Handshake> Peer::create_handshake(
    const NoiseProtocolId &nid,
    const x25519_key &server_privkey,
    const x25519_key *pubkey,
    std::span<const uint8_t, 32> psk,
    int role) {
    Handshake hs;
    int err;

    if (role == NOISE_ROLE_INITIATOR && !pubkey)
        throw std::runtime_error("remote pubkey not provided for initiator");

    {
        NoiseHandshakeState *_hs;
        err = noise_handshakestate_new_by_id(&_hs, &nid, role);
        if (err == NOISE_ERROR_NONE)
            hs = Handshake(_hs);
        else
            throw std::system_error(err, noise_category(), "noise_handshakestate_new_by_id");
    }

    err = noise_handshakestate_set_prologue(hs.get(), WIREGUARD_IDENTIFIER, strlen(WIREGUARD_IDENTIFIER));
    if (err != NOISE_ERROR_NONE)
        throw std::system_error(err, noise_category(), "noise_handshakestate_set_prologue");

    if (!sodium_is_zero(psk.data(), psk.size())) {
        err = noise_handshakestate_set_pre_shared_key(hs.get(), psk.data(), psk.size());
        if (err != NOISE_ERROR_NONE)
            throw std::system_error(err, noise_category(), "noise_handshakestate_set_pre_shared_key");
    }

    auto dhl = noise_handshakestate_get_local_keypair_dh(hs.get());
    err = noise_dhstate_set_keypair_private(dhl, &server_privkey.key[0], std::size(server_privkey.key));
    if (err != NOISE_ERROR_NONE)
        throw std::system_error(err, noise_category(), "noise_dhstate_set_keypair_private");

    if (role == NOISE_ROLE_INITIATOR) {
        auto dhr = noise_handshakestate_get_remote_public_key_dh(hs.get());
        err = noise_dhstate_set_public_key(dhr, &pubkey->key[0], std::size(pubkey->key));
        if (err != NOISE_ERROR_NONE)
            return std::error_code(err, noise_category());
    }

    return hs;
}

void Peer::reset_handshake() {
    _proto = ProtoState();
    _pending = std::monostate{};
}

outcome::result<void> Peer::configure_initiator(
    const x25519_key &server_privkey,
    const x25519_key &pubkey,
    std::span<const uint8_t, 32> psk) {
    reset_handshake();

    auto new_handshake = create_handshake(_nid, server_privkey, &pubkey, psk, NOISE_ROLE_INITIATOR);
    if (new_handshake.has_value())
        _proto.handshake = std::move(new_handshake.value());
    else
        return new_handshake.error();
    auto err = noise_handshakestate_start(_proto.handshake.get());
    if (err != NOISE_ERROR_NONE)
        return std::error_code(err, noise_category());
    return outcome::success();
}

outcome::result<void> Peer::configure_responder(const x25519_key &server_privkey, std::span<const uint8_t, 32> psk) {
    reset_handshake();

    auto new_handshake = create_handshake(_nid, server_privkey, nullptr, psk, NOISE_ROLE_RESPONDER);
    if (new_handshake.has_value())
        _proto.handshake = std::move(new_handshake.value());
    else
        return new_handshake.error();
    auto err = noise_handshakestate_start(_proto.handshake.get());
    if (err != NOISE_ERROR_NONE)
        return std::error_code(err, noise_category());
    return outcome::success();
}

outcome::result<void> Peer::write_handshake_raw(NoiseHandshakeState *hs, NoiseBuffer *out) {
    if (!hs)
        throw std::runtime_error("no active handshake");
    if (noise_handshakestate_get_action(hs) != NOISE_ACTION_WRITE_MESSAGE)
        throw std::runtime_error("handshake in incorrect state for write");

    NoiseBuffer payload;
    noise_buffer_init(payload);

    auto err = noise_handshakestate_write_message(hs, out, &payload);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));
}

outcome::result<void> Peer::write_handshake_raw(NoiseHandshakeState *hs, TAI64N now, NoiseBuffer *out) {
    if (!hs)
        throw std::runtime_error("no active handshake");
    if (noise_handshakestate_get_action(hs) != NOISE_ACTION_WRITE_MESSAGE)
        throw std::runtime_error("handshake in incorrect state for write");

    NoiseBuffer payload;
    noise_buffer_set_input(payload, &now.bytes[0], std::size(now.bytes));

    auto err = noise_handshakestate_write_message(hs, out, &payload);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));
}

outcome::result<void> Peer::read_handshake_raw(NoiseHandshakeState *hs, NoiseBuffer *in, NoiseBuffer *out) {
    if (!hs)
        throw std::runtime_error("no active handshake");
    if (noise_handshakestate_get_action(hs) != NOISE_ACTION_READ_MESSAGE)
        throw std::runtime_error("handshake in incorrect state for read");

    auto err = noise_handshakestate_read_message(hs, in, out);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));
}

outcome::result<void> Peer::make_mac1key(const x25519_key &pubkey, std::array<uint8_t, 64> &out) {
    auto err = noise_hashstate_hash_two(
        _blake2s.get(),
        WIREGUARD_LABEL_MAC1,
        strlen(WIREGUARD_LABEL_MAC1),
        &pubkey.key[0],
        std::size(pubkey.key),
        &out[0],
        32);
    if (err != NOISE_ERROR_NONE)
        // I feel like this should be fatal but whatever
        return outcome::failure(std::error_code(err, noise_category()));
    return outcome::success();
}

outcome::result<void> Peer::calculate_mac1(
    const x25519_key &pubkey,
    std::span<const uint8_t> payload,
    std::span<uint8_t, 16> out) {
    std::array<uint8_t, 64> mac1key = {0};
    auto_cleanup zeroize([&] { sodium_memzero(mac1key.data(), mac1key.size()); });
    BOOST_OUTCOME_TRY(make_mac1key(pubkey, mac1key));
    auto err = noise_hashstate_hash_two(
        _blake2s.get(),
        mac1key.data(),
        mac1key.size(),
        payload.data(),
        payload.size(),
        out.data(),
        out.size());
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));
}

outcome::result<Handshake1 *> Peer::write_handshake1(timespec now, const x25519_key &pubkey, std::span<uint8_t> out) {
    if (noise_handshakestate_get_role(_proto.handshake.get()) != NOISE_ROLE_INITIATOR ||
        noise_handshakestate_get_action(_proto.handshake.get()) != NOISE_ACTION_WRITE_MESSAGE ||
        !std::holds_alternative<std::monostate>(_pending))
        return outcome::failure(std::error_code(EINVAL, std::generic_category()));
    if (out.size() < sizeof(Handshake1))
        return outcome::failure(std::error_code(ENOBUFS, std::generic_category()));
    sodium_memzero(out.data(), sizeof(Handshake1));

    auto hs1 = tdutil::start_lifetime_as<Handshake1>(out.data());
    auto_cleanup zeroize_result([=] { sodium_memzero(hs1, sizeof(Handshake1)); });
    hs1->message_type_and_zeroes = MessageType::First;
    hs1->sender_index = _local_index;
    auto hsb = noise_output(hs1->handshake);
    BOOST_OUTCOME_TRY(write_handshake_raw(_proto.handshake.get(), TAI64N(now), &hsb));
    BOOST_OUTCOME_TRY(calculate_mac1(
        pubkey,
        std::span<const uint8_t>(reinterpret_cast<uint8_t *>(hs1), offsetof(Handshake1, mac1)),
        std::span(hs1->mac1)));

    if (now < _proto.cookie_until && !sodium_is_zero(_proto.cookie.data(), _proto.cookie.size())) {
        auto err = noise_hashstate_hash_two(
            _blake2s.get(),
            _proto.cookie.data(),
            _proto.cookie.size(),
            reinterpret_cast<uint8_t *>(hs1),
            offsetof(Handshake1, mac2),
            &hs1->mac2[0],
            std::size(hs1->mac2));
        if (err != NOISE_ERROR_NONE)
            return outcome::failure(std::error_code(err, noise_category()));
    }

    zeroize_result.reset();
    return hs1;
}

outcome::result<const Handshake2 *> Peer::decode_handshake2(std::span<const uint8_t> in) {
    if (in.size() != sizeof(Handshake2))
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));
    auto hs2 = tdutil::start_lifetime_as<Handshake2>(in.data());
    if (hs2->message_type_and_zeroes != MessageType::Second)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));
    return hs2;
}

outcome::result<void> Peer::read_handshake2(const Handshake2 *hs2, timespec now, const x25519_key &pubkey) {
    if (noise_handshakestate_get_role(_proto.handshake.get()) != NOISE_ROLE_INITIATOR ||
        noise_handshakestate_get_action(_proto.handshake.get()) != NOISE_ACTION_READ_MESSAGE ||
        !std::holds_alternative<std::monostate>(_pending))
        return outcome::failure(std::error_code(EINVAL, std::generic_category()));

    uint32_t rid = hs2->sender_index, lid = hs2->receiver_index;
    if (lid != _local_index)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));
    auto hsb = noise_input(hs2->handshake);
    BOOST_OUTCOME_TRY(read_handshake_raw(_proto.handshake.get(), &hsb, nullptr));
    if (noise_handshakestate_get_action(_proto.handshake.get()) != NOISE_ACTION_SPLIT)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));

    std::array<uint8_t, 32> key1, key2;
    auto_cleanup zeroize([&] {
        sodium_memzero(key1.data(), key1.size());
        sodium_memzero(key2.data(), key2.size());
    });
    size_t len1 = key1.size(), len2 = key2.size();
    auto err = noise_handshakestate_split_raw(_proto.handshake.get(), key1.data(), &len1, key2.data(), &len2);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));

    // commit
    _session.role = NOISE_ROLE_INITIATOR;
    _session.remote_index = rid;
    std::copy(key1.begin(), key1.begin() + len1, _session.key1.begin());
    std::copy(key2.begin(), key2.begin() + len2, _session.key2.begin());
    //_key_until = now +
    return outcome::success();
}

outcome::result<const Handshake1 *> Peer::decode_handshake1(std::span<const uint8_t> in) {
    if (in.size() != sizeof(Handshake1))
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));
    auto hs1 = tdutil::start_lifetime_as<Handshake1>(in.data());
    if (hs1->message_type_and_zeroes != MessageType::First)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));
    return hs1;
}

outcome::result<void> Peer::read_handshake1(const Handshake1 *hs1, timespec now, const x25519_key &pubkey) {
    if (noise_handshakestate_get_role(_proto.handshake.get()) != NOISE_ROLE_RESPONDER ||
        noise_handshakestate_get_action(_proto.handshake.get()) != NOISE_ACTION_READ_MESSAGE ||
        !std::holds_alternative<std::monostate>(_pending))
        return outcome::failure(std::error_code(EINVAL, std::generic_category()));

    // TODO: verify mac2

    std::array<uint8_t, 16> mac1test;
    BOOST_OUTCOME_TRY(calculate_mac1(
        pubkey,
        std::span(reinterpret_cast<const uint8_t *>(hs1), offsetof(Handshake1, mac1)),
        std::span(mac1test)));
    if (sodium_memcmp(&mac1test[0], &hs1->mac1[0], std::size(mac1test)) != 0)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));

    auto rid = hs1->sender_index;
    auto hsb = noise_input(std::span(hs1->handshake));
    TAI64N remote_tm;
    auto tmb = noise_output(std::span(remote_tm.bytes));
    BOOST_OUTCOME_TRY(read_handshake_raw(_proto.handshake.get(), &hsb, &tmb));
    if (remote_tm <= _last_tm)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));

    HalfSessionState pending;
    pending.role = NOISE_ROLE_RESPONDER;
    pending.remote_index = rid;
    _pending = pending;
    return outcome::success();
}

outcome::result<std::span<uint8_t>> Peer::write_handshake2(
    timespec now,
    const x25519_key &pubkey,
    std::span<uint8_t> out) {
    auto half = std::get_if<HalfSessionState>(&_pending);
    if (noise_handshakestate_get_role(_proto.handshake.get()) != NOISE_ROLE_RESPONDER ||
        noise_handshakestate_get_action(_proto.handshake.get()) != NOISE_ACTION_WRITE_MESSAGE || !half)
        return outcome::failure(std::error_code(EINVAL, std::generic_category()));

    // TODO
    if (out.size() < sizeof(Handshake2))
        return outcome::failure(std::error_code(ENOBUFS, std::generic_category()));
    sodium_memzero(out.data(), sizeof(Handshake2));

    auto hs2 = tdutil::start_lifetime_as<Handshake2>(out.data());
    auto_cleanup zeroize_result([=] { sodium_memzero(hs2, sizeof(Handshake2)); });
    hs2->message_type_and_zeroes = MessageType::Second;
    hs2->sender_index = _local_index;
    hs2->receiver_index = half->remote_index;
    auto hsb = noise_output(hs2->handshake);
    BOOST_OUTCOME_TRY(write_handshake_raw(_proto.handshake.get(), &hsb));
    if (noise_handshakestate_get_action(_proto.handshake.get()) != NOISE_ACTION_SPLIT)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));

    BOOST_OUTCOME_TRY(calculate_mac1(
        pubkey,
        std::span<const uint8_t>(reinterpret_cast<uint8_t *>(hs2), offsetof(Handshake2, mac1)),
        std::span(hs2->mac1)));

    if (now < _proto.cookie_until && !sodium_is_zero(_proto.cookie.data(), _proto.cookie.size())) {
        auto err = noise_hashstate_hash_two(
            _blake2s.get(),
            _proto.cookie.data(),
            _proto.cookie.size(),
            reinterpret_cast<uint8_t *>(hs2),
            offsetof(Handshake2, mac2),
            &hs2->mac2[0],
            std::size(hs2->mac2));
        if (err != NOISE_ERROR_NONE)
            return outcome::failure(std::error_code(err, noise_category()));
    }

    SessionState pending;
    pending.role = half->role;
    pending.remote_index = half->remote_index;
    size_t len1 = pending.key1.size(), len2 = pending.key2.size();
    auto err =
        noise_handshakestate_split_raw(_proto.handshake.get(), pending.key1.data(), &len1, pending.key2.data(), &len2);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));
    // pending.key_until;
    _pending = std::move(pending);
    return outcome::success();
}

} // namespace wireglider::proto
