#pragma once

#include <memory>  // IWYU pragma: keep
#include <utility> // IWYU pragma: keep
#include "ppmap.hpp"

#define DISPOSABLE(T)                        \
    T(const T &) = delete;                   \
    T &operator=(const T &) = delete;        \
    T(T &&other) noexcept {                  \
        using std::swap;                     \
        swap(*this, other);                  \
    }                                        \
    T &operator=(T &&other) noexcept {       \
        using std::swap;                     \
        if (this != std::addressof(other)) { \
            this->dispose();                 \
            swap(*this, other);              \
        }                                    \
        return *this;                        \
    }                                        \
    ~T() {                                   \
        this->dispose();                     \
    }

#define DISPOSABLE_COPYABLE(T)               \
    T(const T &) = default;                  \
    T &operator=(const T &) = default;       \
    T(T &&other) noexcept {                  \
        using std::swap;                     \
        swap(*this, other);                  \
    }                                        \
    T &operator=(T &&other) noexcept {       \
        using std::swap;                     \
        if (this != std::addressof(other)) { \
            this->dispose();                 \
            swap(*this, other);              \
        }                                    \
        return *this;                        \
    }                                        \
    ~T() {                                   \
        this->dispose();                     \
    }

#define MAP_DISPOSE_MEMBER_(member) member = std::move(other.member);
#define MAP_DISPOSE_MEMBER(...) PPMAP_EVAL(PPMAP_MAP(MAP_DISPOSE_MEMBER_, __VA_ARGS__))

#define DEFAULT_DISPOSE(T, members...) \
    void dispose() noexcept {          \
        T other{};                     \
        MAP_DISPOSE_MEMBER(members);   \
    }

#define MAP_SWAP_MEMBER_(member) swap(self.member, other.member);
#define MAP_SWAP_MEMBER(...) PPMAP_EVAL(PPMAP_MAP(MAP_SWAP_MEMBER_, __VA_ARGS__))

#define DEFAULT_SWAP(T, members...)                \
    friend void swap(T &self, T &other) noexcept { \
        using std::swap;                           \
        MAP_SWAP_MEMBER(members);                  \
    }
