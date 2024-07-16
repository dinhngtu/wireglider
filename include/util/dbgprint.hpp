#pragma once

#include <fmt/format.h>

#if DEBUG
#define DBG_PRINT(...) fmt::print(__VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif
