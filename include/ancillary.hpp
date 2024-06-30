#pragma once

#include <cstddef>
#include <array>
#include <tuple>
#include <utility>
#include <sys/socket.h>

namespace wgss {

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

    void set(msghdr &mh) {
        mh.msg_control = _storage.data();
        mh.msg_controllen = _storage.size();
    }

    template <size_t Idx>
    void setmsg(int level, int type, const type_at<Idx> &val) {
        size_t off = calc_off<Idx>();
        cmsghdr *cm = reinterpret_cast<cmsghdr *>(&_storage[off]);
        cm->cmsg_level = level;
        cm->cmsg_type = type;
        cm->cmsg_len = len_one<type_at<Idx>>();
        *reinterpret_cast<type_at<Idx> *>(CMSG_DATA(cm)) = val;
    }

private:
    union {
        std::array<uint8_t, space()> _storage = {0};
        cmsghdr _align;
    };
};

} // namespace wgss
