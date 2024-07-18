#pragma once

#include <cassert>
#include <cstdint>
#include <cstddef>
#include <utility>
#include <array>
#include <vector>
#include <memory>
#include <span>
#include <sys/uio.h>
#include <mimalloc.h>

struct sq_ticket {
    constexpr sq_ticket() {
    }
    virtual ~sq_ticket() = default;
};
