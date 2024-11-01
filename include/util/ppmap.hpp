#pragma once

// https://stackoverflow.com/a/45586169

#define PPMAP_FIRST_(a, ...) a
#define PPMAP_SECOND_(a, b, ...) b

#define PPMAP_FIRST(...) PPMAP_FIRST_(__VA_ARGS__, )
#define PPMAP_SECOND(...) PPMAP_SECOND_(__VA_ARGS__, )

#define PPMAP_EMPTY()

#define PPMAP_EVAL1024(...) PPMAP_EVAL512(PPMAP_EVAL512(__VA_ARGS__))
#define PPMAP_EVAL512(...) PPMAP_EVAL256(PPMAP_EVAL256(__VA_ARGS__))
#define PPMAP_EVAL256(...) PPMAP_EVAL128(PPMAP_EVAL128(__VA_ARGS__))
#define PPMAP_EVAL128(...) PPMAP_EVAL64(PPMAP_EVAL64(__VA_ARGS__))
#define PPMAP_EVAL64(...) PPMAP_EVAL32(PPMAP_EVAL32(__VA_ARGS__))
#define PPMAP_EVAL32(...) PPMAP_EVAL16(PPMAP_EVAL16(__VA_ARGS__))
#define PPMAP_EVAL16(...) PPMAP_EVAL8(PPMAP_EVAL8(__VA_ARGS__))
#define PPMAP_EVAL8(...) PPMAP_EVAL4(PPMAP_EVAL4(__VA_ARGS__))
#define PPMAP_EVAL4(...) PPMAP_EVAL2(PPMAP_EVAL2(__VA_ARGS__))
#define PPMAP_EVAL2(...) PPMAP_EVAL1(PPMAP_EVAL1(__VA_ARGS__))
#define PPMAP_EVAL1(...) __VA_ARGS__

#ifndef PPMAP_EVAL_MAX
#define PPMAP_EVAL_MAX PPMAP_EVAL8
#endif
#define PPMAP_EVAL(...) PPMAP_EVAL_MAX(__VA_ARGS__)

#define PPMAP_DEFER1(m) m PPMAP_EMPTY()
#define PPMAP_DEFER2(m) m PPMAP_EMPTY PPMAP_EMPTY()()

#define PPMAP_IS_PROBE(...) PPMAP_SECOND(__VA_ARGS__, 0)
#define PPMAP_PROBE() ~, 1

#define PPMAP_CAT(a, b) a##b

#define PPMAP_NOT(x) PPMAP_IS_PROBE(PPMAP_CAT(PPMAP__NOT_, x))
#define PPMAP__NOT_0 PPMAP_PROBE()

#define PPMAP_BOOL(x) PPMAP_NOT(PPMAP_NOT(x))

#define PPMAP_IF_ELSE(condition) PPMAP__IF_ELSE(PPMAP_BOOL(condition))
#define PPMAP__IF_ELSE(condition) PPMAP_CAT(PPMAP__IF_, condition)

#define PPMAP__IF_1(...) __VA_ARGS__ PPMAP__IF_1_ELSE
#define PPMAP__IF_0(...) PPMAP__IF_0_ELSE

#define PPMAP__IF_1_ELSE(...)
#define PPMAP__IF_0_ELSE(...) __VA_ARGS__

#define PPMAP_HAS_ARGS(...) PPMAP_BOOL(PPMAP_FIRST(PPMAP__END_OF_ARGUMENTS_ __VA_ARGS__)())
#define PPMAP__END_OF_ARGUMENTS_() 0

#define PPMAP_MAP(m, first, ...)                                                     \
    m(first) PPMAP_IF_ELSE(PPMAP_HAS_ARGS(__VA_ARGS__))(                             \
        PPMAP_DEFER2(PPMAP__MAP)()(m, __VA_ARGS__))(/* Do nothing, just terminate */ \
    )
#define PPMAP__MAP() PPMAP_MAP
