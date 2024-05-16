#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>


SEC("xdp")
int parse_drop(struct xdp_md *ctx)
{

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

    return XDP_DROP;
}