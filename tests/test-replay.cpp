#include <catch2/catch_test_macros.hpp>

#include "replay.hpp"

#define T(val, expect) REQUIRE(filter.try_advance(val) == (expect));

TEST_CASE("replay") {
    const uint64_t RejectAfterMessages = 18446744073709543423ull;
    wireglider::proto::ReplayRing<uint64_t, 8192> filter(RejectAfterMessages);
    const uint64_t windowSize = filter.window_size();
    const uint64_t T_LIM = windowSize + 1;
    REQUIRE(windowSize == 8128);
    SECTION("1") {
        T(0, true);                        /*  1 */
        T(1, true);                        /*  2 */
        T(1, false);                       /*  3 */
        T(9, true);                        /*  4 */
        T(8, true);                        /*  5 */
        T(7, true);                        /*  6 */
        T(7, false);                       /*  7 */
        T(T_LIM, true);                    /*  8 */
        T(T_LIM - 1, true);                /*  9 */
        T(T_LIM - 1, false);               /* 10 */
        T(T_LIM - 2, true);                /* 11 */
        T(2, true);                        /* 12 */
        T(2, false);                       /* 13 */
        T(T_LIM + 16, true);               /* 14 */
        T(3, false);                       /* 15 */
        T(T_LIM + 16, false);              /* 16 */
        T(T_LIM * 4, true);                /* 17 */
        T(T_LIM * 4 - (T_LIM - 1), true);  /* 18 */
        T(10, false);                      /* 19 */
        T(T_LIM * 4 - T_LIM, false);       /* 20 */
        T(T_LIM * 4 - (T_LIM + 1), false); /* 21 */
        T(T_LIM * 4 - (T_LIM - 2), true);  /* 22 */
        T(T_LIM * 4 + 1 - T_LIM, false);   /* 23 */
        T(0, false);                       /* 24 */
        T(RejectAfterMessages, false);     /* 25 */
        T(RejectAfterMessages - 1, true);  /* 26 */
        T(RejectAfterMessages, false);     /* 27 */
        T(RejectAfterMessages - 1, false); /* 28 */
        T(RejectAfterMessages - 2, true);  /* 29 */
        T(RejectAfterMessages + 1, false); /* 30 */
        T(RejectAfterMessages + 2, false); /* 31 */
        T(RejectAfterMessages - 2, false); /* 32 */
        T(RejectAfterMessages - 3, true);  /* 33 */
        T(0, false);                       /* 34 */
    }

    SECTION("Bulk test 1") {
        for (uint64_t i = 1; i <= windowSize; i++) {
            T(i, true);
        }
        T(0, true);
        T(0, false);
    }

    SECTION("Bulk test 2") {
        for (uint64_t i = 2; i <= windowSize + 1; i++) {
            T(i, true);
        }
        T(1, true);
        T(0, false);
    }

    SECTION("Bulk test 3") {
        for (uint64_t i = windowSize + 1; i > 0; i--) {
            T(i, true);
        }
    }

    SECTION("Bulk test 4") {
        for (uint64_t i = windowSize + 2; i > 1; i--) {
            T(i, true);
        }
        T(0, false);
    }

    SECTION("Bulk test 5") {
        for (uint64_t i = windowSize; i > 0; i--) {
            T(i, true);
        }
        T(windowSize + 1, true);
        T(0, false);
    }

    SECTION("Bulk test 6") {
        for (uint64_t i = windowSize; i > 0; i--) {
            T(i, true);
        }
        T(0, true);
        T(windowSize + 1, true);
    }
}
