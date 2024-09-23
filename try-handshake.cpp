#include "proto.hpp"
#include "tai64n.hpp"

using namespace wireglider::proto;

static outcome::result<void> doit() {
    TAI64NClock clk;
    Peer peer(0x12345);
}

int main() {
    auto res = doit();
    if (res)
        return 0;
    else
        return res.error().value();
}
