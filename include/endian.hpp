#pragma once

#include <utility>
#include <type_traits>
#include <boost/endian.hpp>

// native_to_* functions are unsafe: if its argument is of a different size from the lvalue then the swapped value will
// be truncated, and things will explode.
// thus the replacement functions.

namespace wgss {

template <typename TDest, typename TSrc>
constexpr void assign_big_from_native(TDest &lhs, TSrc &&rhs) noexcept {
    lhs = boost::endian::native_to_big(static_cast<TDest>(std::forward<TSrc>(rhs)));
}

template <typename TDest, typename TSrc>
constexpr void assign_little_from_native(TDest &lhs, TSrc &&rhs) noexcept {
    lhs = boost::endian::native_to_little(static_cast<TDest>(std::forward<TSrc>(rhs)));
}

template <boost::endian::order Endian, typename T>
struct EndianVal {
    using value_type = std::remove_cvref_t<T>;
    constexpr EndianVal(const T &ref) noexcept : _val(ref) {
    }
    value_type _val;
};

template <boost::endian::order Endian, typename T>
struct EndianRef {
    constexpr EndianRef(T &ref) noexcept : _ref(ref) {
    }
    template <boost::endian::order From, typename TSrc>
    constexpr T &operator=(EndianRef<From, TSrc> other) noexcept {
        _ref = boost::endian::conditional_reverse<From, Endian>(static_cast<T>(other._ref));
        return _ref;
    }
    template <boost::endian::order From, typename TSrc>
    constexpr T &operator=(EndianVal<From, TSrc> other) noexcept {
        _ref = boost::endian::conditional_reverse<From, Endian>(static_cast<T>(other._val));
        return _ref;
    }
    template <typename TSrc>
    constexpr T &operator=(T other) noexcept {
        _ref = boost::endian::conditional_reverse<boost::endian::order::native, Endian>(static_cast<T>(other));
        return _ref;
    }
    T &_ref;
};

template <typename T>
constexpr EndianVal<boost::endian::order::native, T> native_ref(T &&val) noexcept {
    return EndianVal<boost::endian::order::native, T>(val);
}
template <typename T>
constexpr EndianRef<boost::endian::order::native, T> native_ref(T &val) noexcept {
    return EndianRef<boost::endian::order::native, T>(val);
}
template <typename T>
constexpr EndianVal<boost::endian::order::native, T> native_ref(const T &val) noexcept {
    return EndianVal<boost::endian::order::native, T>(val);
}

template <typename T>
constexpr EndianVal<boost::endian::order::big, T> big_ref(T &&val) noexcept {
    return EndianVal<boost::endian::order::big, T>(val);
}
template <typename T>
constexpr EndianRef<boost::endian::order::big, T> big_ref(T &val) noexcept {
    return EndianRef<boost::endian::order::big, T>(val);
}
template <typename T>
constexpr EndianVal<boost::endian::order::big, T> big_ref(const T &val) noexcept {
    return EndianVal<boost::endian::order::big, T>(val);
}

template <typename T>
constexpr EndianVal<boost::endian::order::little, T> little_ref(T &&val) noexcept {
    return EndianVal<boost::endian::order::little, T>(val);
}
template <typename T>
constexpr EndianRef<boost::endian::order::little, T> little_ref(T &val) noexcept {
    return EndianRef<boost::endian::order::little, T>(val);
}
template <typename T>
constexpr EndianVal<boost::endian::order::little, T> little_ref(const T &val) noexcept {
    return EndianVal<boost::endian::order::little, T>(val);
}

} // namespace wgss
