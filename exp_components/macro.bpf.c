#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

#include "mykperf_module.h"
BPF_MYKPERF_INIT_TRACE();
DEFINE_SECTIONS("main");

SEC("xdp")
int macro(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE_ARRAY(main);

    // parse eth pkt
    void *data_end = (void *)(long)(ctx->data_end);
    void *data = (void *)(long)(ctx->data);
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) <= data_end)
    {
        if (eth->h_proto != bpf_htons(ETH_P_IP))
        {
            struct iphdr *ip = data + sizeof(*eth);
            if ((void *)ip + sizeof(*ip) <= data_end)
            {
                return XDP_DROP;
            }
        }
    }

    BPF_MYKPERF_END_TRACE_ARRAY(main);

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";