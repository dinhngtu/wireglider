#include <fmt/format.h>
#include "worker/flowkey_ref.hpp"

#define PRINT(x) fmt::print(#x " = {}\n", wireglider::worker_impl::FlowkeyRefMeta::x);

int main() {
    PRINT(PacketRefBatchSize);
    PRINT(IP4RefFlowSize);
    PRINT(IP4FlowKeySize);
    PRINT(IP4FlowValueSize);
    PRINT(IP6RefFlowSize);
    PRINT(IP6FlowKeySize);
    PRINT(IP6FlowValueSize);
    PRINT(DecapRefUnrelSize);
    PRINT(DecapRefRetpktSize);
    PRINT(DecapRefBatchSize);
    return 0;
}
