#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE();
DEFINE_SECTIONS("main");

SEC("xdp")
int drop_sr(struct xdp_md *ctx)
{

    BPF_MYKPERF_START_TRACE_MULTIPLEXED_SAMPLED(main);

/*     // parse packt
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return XDP_DROP;
    } */

    BPF_MYKPERF_END_TRACE_MULTIPLEXED(main);

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";