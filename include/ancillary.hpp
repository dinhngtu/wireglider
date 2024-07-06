#pragma once

#include <cstddef>
#include <cstring>
#include <array>
#include <tuple>
#include <utility>
#include <sys/socket.h>

namespace wireglider {

template <typename... Ts>
class AncillaryData {
    template <size_t Idx>
    using type_at = std::tuple_element_t<Idx, std::tuple<Ts...>>;

    template <typename T>
    static constexpr size_t space_one() {
        return CMSG_SPACE(sizeof(T));
    }

    template <typename T>
    static constexpr size_t len_one() {
        return CMSG_LEN(sizeof(T));
    }

    template <size_t Idx, size_t Limit>
    static constexpr size_t off_one() {
        return (Idx < Limit) ? space_one<type_at<Idx>>() : 0;
    }

    template <size_t Limit, size_t... I>
    static constexpr size_t calc_off_impl(std::index_sequence<I...>) {
        return (off_one<I, Limit>() + ... + 0);
    }

    template <size_t Limit, typename Indexes = std::index_sequence_for<Ts...>>
    static constexpr size_t calc_off() {
        return calc_off_impl<Limit>(Indexes{});
    }

public:
    static constexpr size_t space() {
        return (space_one<Ts>() + ... + 0);
    }

    constexpr AncillaryData() {
    }

    constexpr explicit AncillaryData(msghdr &mh) {
        mh.msg_control = _storage.data();
        mh.msg_controllen = _storage.size();
    }

    template <size_t Idx>
    void set(int level, int type, const type_at<Idx> &val) {
        size_t off = calc_off<Idx>();
        cmsghdr cm{
            .cmsg_len = len_one<type_at<Idx>>(),
            .cmsg_level = level,
            .cmsg_type = type,
        };
        memcpy(&_storage[off], &cm, sizeof(cm));
        memcpy(CMSG_DATA(reinterpret_cast<cmsghdr *>(&_storage[off])), &val, sizeof(val));
    }

    constexpr std::array<uint8_t, space()>::const_iterator begin() const {
        return _storage.begin();
    }

    constexpr std::array<uint8_t, space()>::const_iterator end() const {
        return _storage.end();
    }

private:
    union {
        std::array<uint8_t, space()> _storage = {0};
        cmsghdr _align;
    };
};

} // namespace wireglider
