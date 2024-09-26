#include <cstring>
#include <stdexcept>
#include <string_view>
#include <boost/algorithm/hex.hpp>
#include <boost/endian/conversion.hpp>
#include <noise/protocol/constants.h>
#include <noise/protocol/hashstate.h>
#include <blake2.h>
#include <tdutil/util.hpp>

#include "proto.hpp"
#include "dbgprint.hpp"
#include "keys.hpp"
#include "util/base64.hpp"

/*
 * Protocol conformance:
 *
 * - A handshake initiation is retried after REKEY_TIMEOUT + jitter ms, if a response has not been received, where
 * jitter is some random value between 0 and 333 ms. [Proto tick OK, Timer]
 *
 * - If a packet has been received from a given peer, but we have not sent one back to the given peer in KEEPALIVE ms,
 * we send an empty packet. [Proto recv OK, tick OK, Timer]
 *
 * - If we have sent a packet to a given peer but have not received a packet after from that peer for KEEPALIVE +
 * REKEY_TIMEOUT ms, we initiate a new handshake. [Proto send OK, tick OK, Timer]
 *
 * - All ephemeral private keys and symmetric session keys are zeroed out after REJECT_AFTER_TIME * 3 ms if no new keys
 * have been exchanged. [Proto tick OK, Timer?]
 *
 * - After sending a packet, if the number of packets sent using that key exceeds REKEY_AFTER_MESSAGES, we initiate a
 * new handshake. [Proto OK]
 *
 * - After sending a packet, if the sender was the original initiator of the handshake and if the current session key is
 * REKEY_AFTER_TIME ms old, we initiate a new handshake. If the sender was the original responder of the handshake, we
 * do not reinitiate a new handshake after REKEY_AFTER_TIME ms like the original initiator does. [Proto OK]
 *
 * - After receiving a packet, if the receiver was the original initiator of the handshake and if the current session
 * key is REKEY_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT ms old, we initiate a new handshake. [Proto OK]
 *
 * - Handshakes are only initiated once every REKEY_TIMEOUT ms, with this strict rate limiting enforced.
 *
 * - Packets are dropped if the session counter is greater than REJECT_AFTER_MESSAGES or if its key is older than
 * REJECT_AFTER_TIME ms. [Proto OK]
 *
 * - After REKEY_ATTEMPT_TIME ms of trying to initiate a new handshake, the retries give up and cease, and clear all
 * existing packets queued up to be sent. If a packet is explicitly queued up to be sent, then this timer is reset.
 * [Proto tick OK, Timer]
 *
 * - After a handshake is completed, with a message from initiator to responder and then responder back to initiator,
 * the initiator may then send encrypted session packets, but the responder cannot. The responder must wait to use the
 * new session until it has recieved one encrypted session packet from the initiator, in order to provide key
 * confirmation. Thus, until the responder receives that first packet using the newly established session, it must
 * either queue up packets to be sent later, or use the previous session, if one exists and is valid. Therefore, after
 * the initiator receives the response from the responder, if it has no data packets immediately queued up to send, it
 * should send an empty packet, so as to provide this confirmation. [Proto session cache OK, encap caching OK, initiator
 * handshake empty packet not implemented]
 */

using namespace boost::endian;
using namespace tdutil;
using namespace tdutil::operators;
using namespace wireglider;
using namespace wireglider::time;

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

[[maybe_unused]] static constexpr NoiseBuffer noise_inout(std::span<uint8_t> span, size_t datasize) {
    NoiseBuffer ret;
    noise_buffer_set_inout(ret, span.data(), datasize, span.size());
    return ret;
}

namespace wireglider {

bool parse_keybytes(uint8_t (&key)[32], const char *str) { // NOLINT(cppcoreguidelines-avoid-c-arrays)
    auto s = std::string_view(str);
    switch (s.length()) {
    case 64:
        /*
        for (auto i = 0; i < 32; i++) {
            auto res = std::from_chars(&s[i], &s[i + 2], key[i], 16);
            if (res.ec != std::errc{} || res.ptr != &s[i + 2])
                return false;
        }
        */
        return boost::algorithm::unhex(s.begin(), s.end(), std::begin(key)) == std::end(key);
    case 43:
    case 44: {
        auto [written, read] = wireglider::base64::decode(&key[0], s.data(), s.size());
        return written == 32;
    }
    default:
        return false;
    }
}

} // namespace wireglider

namespace wireglider::proto {

enum class MessageType : uint32_t {
    First = 1,
    Second = 2,
    Cookie = 3,
    Data = 4,
};

std::string NoiseErrorCategory::message(int cond) const {
    return noise_errstr(cond);
}

Peer::Peer(uint32_t index) : _nid(make_proto_id().value()), _local_index(index) {
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
    const Key256 &server_privkey,
    const Key256 *pubkey,
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

    err = noise_handshakestate_set_pre_shared_key(hs.get(), psk.data(), psk.size());
    if (err != NOISE_ERROR_NONE)
        throw std::system_error(err, noise_category(), "noise_handshakestate_set_pre_shared_key");

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

void Peer::reset_handshake(const timespec &now) {
    _proto.handshake.reset();
    _proto.handshake_begin = now;
    _pending = std::monostate{};
}

outcome::result<void> Peer::configure_initiator(
    const timespec &now,
    const Key256 &server_privkey,
    const Key256 &pubkey,
    std::span<const uint8_t, 32> psk) {
    reset_handshake(now);

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

outcome::result<void> Peer::configure_responder(
    const timespec &now,
    const Key256 &server_privkey,
    std::span<const uint8_t, 32> psk) {
    reset_handshake(now);

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

    auto err = noise_handshakestate_write_message(hs, out, nullptr);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));

    return outcome::success();
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

    return outcome::success();
}

outcome::result<void> Peer::read_handshake_raw(NoiseHandshakeState *hs, NoiseBuffer *in, NoiseBuffer *out) {
    if (!hs)
        throw std::runtime_error("no active handshake");
    if (noise_handshakestate_get_action(hs) != NOISE_ACTION_READ_MESSAGE)
        throw std::runtime_error("handshake in incorrect state for read");

    auto err = noise_handshakestate_read_message(hs, in, out);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));

    return outcome::success();
}

Key256 Peer::get_my_pubkey() {
    Key256 my_pubkey;
    auto mydh = noise_handshakestate_get_local_keypair_dh(_proto.handshake.get());
    if (!mydh)
        throw std::runtime_error("cannot get local pubkey");
    auto err = noise_dhstate_get_public_key(mydh, &my_pubkey.key[0], std::size(my_pubkey.key));
    if (err != NOISE_ERROR_NONE)
        throw std::system_error(err, noise_category(), "noise_dhstate_get_public_key");
    return my_pubkey;
}

void Peer::make_mac1key(const Key256 &pubkey, std::span<uint8_t, 32> out) {
    std::array<uint8_t, 8 + 32> in;
    std::copy_n(WIREGUARD_LABEL_MAC1, 8, in.begin());
    std::copy(std::begin(pubkey.key), std::end(pubkey.key), &in[8]);
    auto err = blake2s(out.data(), in.data(), nullptr, out.size(), in.size(), 0);
    if (err)
        throw std::runtime_error("make_mac1key");
}

outcome::result<void> Peer::calculate_mac1(
    const Key256 &pubkey,
    std::span<const uint8_t> payload,
    std::span<uint8_t, 16> out) {
    std::array<uint8_t, 32> mac1key = {0};
    make_mac1key(pubkey, mac1key);
    auto err = blake2s(out.data(), payload.data(), mac1key.data(), out.size(), payload.size(), mac1key.size());
    if (err)
        throw std::runtime_error("calculate_mac1");
    return outcome::success();
}

std::variant<std::monostate, const Handshake1 *, const Handshake2 *, const CookiePacket *, std::span<const uint8_t>>
Peer::decode_pkt(std::span<const uint8_t> in) {
    if (in.size() < sizeof(MessageType))
        return std::monostate{};
    auto mtype = static_cast<MessageType>(load_little_u32(in.data()));
    switch (mtype) {
    case MessageType::First:
        if (in.size() == sizeof(Handshake1))
            return reinterpret_cast<const Handshake1 *>(in.data());
        else
            return std::monostate{};
    case MessageType::Second:
        if (in.size() == sizeof(Handshake2))
            return reinterpret_cast<const Handshake2 *>(in.data());
        else
            return std::monostate{};
    case MessageType::Cookie:
        if (in.size() == sizeof(CookiePacket))
            return reinterpret_cast<const CookiePacket *>(in.data());
        else
            return std::monostate{};
    case MessageType::Data:
        return in;
    default:
        return std::monostate{};
    }
}

outcome::result<Handshake1 *> Peer::write_handshake1(
    const timespec &now,
    const Key256 &pubkey,
    std::span<uint8_t> out) {
    if (!_proto.is_role(NOISE_ROLE_INITIATOR) || !_proto.is_action(NOISE_ACTION_WRITE_MESSAGE) ||
        !std::holds_alternative<std::monostate>(_pending))
        return outcome::failure(std::error_code(EINVAL, std::generic_category()));
    if (out.size() < sizeof(Handshake1))
        return outcome::failure(std::error_code(ENOBUFS, std::generic_category()));
    sodium_memzero(out.data(), sizeof(Handshake1));

    auto hs1 = reinterpret_cast<Handshake1 *>(out.data());
    hs1->message_type_and_zeroes = static_cast<uint32_t>(MessageType::First);
    hs1->sender_index = _local_index;
    auto hsb = noise_output(hs1->handshake);
    BOOST_OUTCOME_TRY(write_handshake_raw(_proto.handshake.get(), TAI64N(now), &hsb));
    BOOST_OUTCOME_TRY(calculate_mac1(
        pubkey,
        std::span<const uint8_t>(reinterpret_cast<uint8_t *>(hs1), offsetof(Handshake1, mac1)),
        std::span(hs1->mac1)));

    if (now < _proto.cookie_until && !sodium_is_zero(_proto.cookie.data(), _proto.cookie.size())) {
        auto err = blake2s(
            std::data(hs1->mac2),
            reinterpret_cast<uint8_t *>(hs1),
            _proto.cookie.data(),
            std::size(hs1->mac2),
            offsetof(Handshake1, mac2),
            _proto.cookie.size());
        if (err)
            throw std::runtime_error("write_handshake1");
    }

    _next_hs1_retry = now + (RekeyTimeout + randombytes_uniform(RekeyTimeoutJitterMaxMs) * OneMillisecond);
    return hs1;
}

outcome::result<void> Peer::read_handshake2(const Handshake2 *hs2, const timespec &now) {
    if (!_proto.is_role(NOISE_ROLE_INITIATOR) || !_proto.is_action(NOISE_ACTION_READ_MESSAGE) ||
        !std::holds_alternative<std::monostate>(_pending))
        return outcome::failure(std::error_code(EINVAL, std::generic_category()));

    auto my_pubkey = get_my_pubkey();

    std::array<uint8_t, 16> mac1test;
    BOOST_OUTCOME_TRY(calculate_mac1(
        my_pubkey,
        std::span(reinterpret_cast<const uint8_t *>(hs2), offsetof(Handshake2, mac1)),
        std::span(mac1test)));
    if (sodium_memcmp(&mac1test[0], &hs2->mac1[0], std::size(mac1test)) != 0)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));

    uint32_t rid = hs2->sender_index, lid = hs2->receiver_index;
    if (lid != _local_index)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));
    auto hsb = noise_input(hs2->handshake);
    BOOST_OUTCOME_TRY(read_handshake_raw(_proto.handshake.get(), &hsb, nullptr));
    if (!_proto.is_action(NOISE_ACTION_SPLIT))
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));

    std::array<uint8_t, 32> skey, rkey;
    auto_cleanup zeroize([&] {
        sodium_memzero(skey.data(), skey.size());
        sodium_memzero(rkey.data(), rkey.size());
    });
    size_t sklen = skey.size(), rklen = rkey.size();
    auto err = noise_handshakestate_split_raw(_proto.handshake.get(), skey.data(), &sklen, rkey.data(), &rklen);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));

    // commit
    _session = SessionState(NOISE_ROLE_INITIATOR, rid, skey.data(), sklen, rkey.data(), rklen, now);
    return outcome::success();
}

outcome::result<void> Peer::read_handshake1(const Handshake1 *hs1) {
    if (!_proto.is_role(NOISE_ROLE_RESPONDER) || !_proto.is_action(NOISE_ACTION_READ_MESSAGE) ||
        !std::holds_alternative<std::monostate>(_pending))
        return outcome::failure(std::error_code(EINVAL, std::generic_category()));

    // TODO: verify mac2

    auto my_pubkey = get_my_pubkey();

    std::array<uint8_t, 16> mac1test;
    BOOST_OUTCOME_TRY(calculate_mac1(
        my_pubkey,
        std::span(reinterpret_cast<const uint8_t *>(hs1), offsetof(Handshake1, mac1)),
        std::span(mac1test)));
    if (sodium_memcmp(&mac1test[0], &hs1->mac1[0], std::size(mac1test)) != 0)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));

    auto rid = hs1->sender_index;
    auto hsb = noise_input(std::span(hs1->handshake));
    TAI64N remote_tm;
    auto tmb = noise_output(std::span(remote_tm.bytes));
    BOOST_OUTCOME_TRY(read_handshake_raw(_proto.handshake.get(), &hsb, &tmb));
    if (remote_tm <= _last_remote_hs1)
        return outcome::failure(std::error_code(ENOENT, std::generic_category()));
    _last_remote_hs1 = remote_tm;

    HalfSessionState pending;
    pending.role = NOISE_ROLE_RESPONDER;
    pending.remote_index = rid;
    _pending = pending;
    return outcome::success();
}

outcome::result<std::span<uint8_t>> Peer::write_handshake2(
    const timespec &now,
    const Key256 &pubkey,
    std::span<uint8_t> out) {
    auto half = std::get_if<HalfSessionState>(&_pending);
    if (!_proto.is_role(NOISE_ROLE_RESPONDER) || !_proto.is_action(NOISE_ACTION_WRITE_MESSAGE) || !half)
        return outcome::failure(std::error_code(EINVAL, std::generic_category()));

    if (out.size() < sizeof(Handshake2))
        return outcome::failure(std::error_code(ENOBUFS, std::generic_category()));
    sodium_memzero(out.data(), sizeof(Handshake2));

    auto hs2 = reinterpret_cast<Handshake2 *>(out.data());
    hs2->message_type_and_zeroes = static_cast<uint32_t>(MessageType::Second);
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
        auto err = blake2s(
            std::data(hs2->mac2),
            reinterpret_cast<uint8_t *>(hs2),
            _proto.cookie.data(),
            std::size(hs2->mac2),
            offsetof(Handshake2, mac2),
            _proto.cookie.size());
        if (err)
            throw std::runtime_error("write_handshake2");
    }

    std::array<uint8_t, 32> key1, key2;
    size_t len1 = key1.size(), len2 = key2.size();
    auto err = noise_handshakestate_split_raw(_proto.handshake.get(), key1.data(), &len1, key2.data(), &len2);
    if (err != NOISE_ERROR_NONE)
        return outcome::failure(std::error_code(err, noise_category()));

    _pending = SessionState(half->role, half->remote_index, key1.data(), len1, key2.data(), len2, now);
    return outcome::success();
}

outcome::result<std::pair<SessionState *, bool>, DecryptError> Peer::decrypt_begin(const timespec &now) {
    SessionState *session = std::get_if<SessionState>(&_pending);
    bool needs_upgrade = false;
    if (session && !session->expired(now))
        needs_upgrade = true;
    else if (_session.exists() && !_session.expired(now))
        session = &_session;
    else
        return DecryptError::NoSession;
    return std::make_pair(session, needs_upgrade);
}

DecryptResult Peer::decrypt(SessionState *session, std::span<uint8_t> out, std::span<const uint8_t> in) {
    if (in.size() < sizeof(DataHeader))
        return DecryptError::Rejected;
    auto hdr = reinterpret_cast<const DataHeader *>(in.data());
    if (hdr->counter > RejectAfterMessages)
        return DecryptError::Rejected;
    auto cryptin = in.subspan(sizeof(DataHeader));

    ProtoSuccess result{
        .outsize = 0,
    };
    std::array<uint8_t, crypto_aead_chacha20poly1305_IETF_NPUBBYTES> nonce = {0};
    store_little_u64(&nonce[4], hdr->counter);
    /*
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out.data(),
            &result.outsize,
            nullptr,
            cryptin.data(),
            cryptin.size(),
            nullptr,
            0,
            &nonce[0],
            session->rkey.data()) < 0)
        return DecryptError::Rejected;
        */
    memmove(out.data(), cryptin.data(), cryptin.size());
    result.outsize = cryptin.size();
    if (!session->replay.try_advance(hdr->counter))
        return DecryptError::Rejected;
    return result;
}

ProtoSignal Peer::decrypt_end(const timespec &now, SessionState *session, bool needs_upgrade) {
    auto signal = ProtoSignal::Ok;
    if (needs_upgrade)
        _session = std::move(*session);
    if (_session.last_send - now > KeepaliveTimeout)
        signal |= ProtoSignal::NeedsKeepalive;
    _session.last_recv = now;
    if (_session.role == NOISE_ROLE_INITIATOR &&
        _session.expired(now, RekeyAfterTime - KeepaliveTimeout - RekeyTimeout))
        signal |= ProtoSignal::NeedsHandshake;
    return signal;
}

outcome::result<void, EncryptError> Peer::encrypt_begin(const timespec &now) {
    if (!_session.exists() || _session.expired(now))
        return EncryptError::NoSession;
    return outcome::success();
}

EncryptResult Peer::encrypt(std::span<uint8_t> out, std::span<const uint8_t> in) {
    if (!_session.exists())
        return EncryptError::NoSession;

    auto padded_size = round_up(in.size(), 16);
    if (out.size() < sizeof(DataHeader) + padded_size + 0)
        return EncryptError::BufferError;

    auto counter = _session.encrypt_nonce++;
    if (counter >= RejectAfterMessages)
        return EncryptError::NoSession;
    store_little_u32(out.data(), static_cast<uint32_t>(MessageType::Data));
    store_little_u32(out.data() + offsetof(DataHeader, receiver_index), _session.remote_index);
    store_little_u64(out.data() + offsetof(DataHeader, counter), counter);
    std::array<uint8_t, crypto_aead_chacha20poly1305_IETF_NPUBBYTES> nonce = {0};
    store_little_u64(&nonce[4], counter);

    auto cryptout = out.subspan(sizeof(DataHeader));
    if (padded_size != in.size()) {
        memcpy(cryptout.data(), in.data(), in.size());
        memset(&cryptout[in.size()], 0, padded_size - in.size());
        in = cryptout.subspan(0, padded_size);
    }

    ProtoSuccess result{
        .outsize = cryptout.size(),
    };
    /*
    crypto_aead_chacha20poly1305_ietf_encrypt(
        cryptout.data(),
        &result.outsize,
        in.data(),
        in.size(),
        nullptr,
        0,
        nullptr,
        nonce.data(),
        _session.skey.data());
        */
    memmove(cryptout.data(), in.data(), in.size());
    result.outsize = padded_size;
    result.outsize += sizeof(DataHeader);
    return result;
}

ProtoSignal Peer::encrypt_end(const timespec &now) {
    auto signal = ProtoSignal::Ok;
    if (_session.encrypt_nonce > RekeyAfterMessages)
        signal |= ProtoSignal::NeedsHandshake;
    if (_session.role == NOISE_ROLE_INITIATOR && _session.expired(now, RekeyAfterTime))
        signal |= ProtoSignal::NeedsHandshake;
    if (_session.last_recv - now > (KeepaliveTimeout + RekeyTimeout))
        signal |= ProtoSignal::NeedsHandshake;
    _session.last_send = now;
    return signal;
}

ProtoSignal Peer::tick(const timespec &now) {
    ProtoSignal signal = ProtoSignal::Ok;
    if (_proto.exists() && _session.expired(now) && (now - _proto.handshake_begin) > RekeyAttemptTime)
        signal |= ProtoSignal::NeedsQueueClear;
    if (_session.exists() && _session.expired(now, 3 * RejectAfterTime)) {
        reset_all(now);
        signal |= ProtoSignal::SessionWasReset;
        return signal;
    }
    if (_proto.is_role(NOISE_ROLE_INITIATOR) && _proto.is_action(NOISE_ACTION_READ_MESSAGE) &&
        (now - _next_hs1_retry) > 0)
        signal |= ProtoSignal::NeedsHandshake;
    if (_session.exists()) {
        if (_session.last_send - now > KeepaliveTimeout)
            signal |= ProtoSignal::NeedsKeepalive;
        if (_session.last_recv - now > (KeepaliveTimeout + RekeyTimeout))
            signal |= ProtoSignal::NeedsHandshake;
    }
    return signal;
}

} // namespace wireglider::proto
