#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

__u64 bpf_mykperf__rdpmc(__u64 counter) __ksym;


SEC("xdp")
int kfunc(struct xdp_md *ctx)
{
    __u64 start = bpf_mykperf__rdpmc(0);

// ---------------------------------------------------
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
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
// ---------------------------------------------------
    __u64 end = bpf_mykperf__rdpmc(0) - start;

    return XDP_DROP;
}