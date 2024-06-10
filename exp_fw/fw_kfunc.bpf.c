#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
// #include <bpf/libbpf.h>
#include "fw.bpf.h"

#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE();
DEFINE_SECTIONS("main");

inline int insert_key(struct flow_ctx_table_key *flow_key)
{
    // swap src and dest
    __u32 temp;
    temp = flow_key->ip_dst;

    __u16 temp1;
    flow_key->ip_dst = flow_key->ip_src;
    flow_key->ip_src = temp;
    temp1 = flow_key->l4_dst;
    flow_key->l4_dst = flow_key->l4_src;
    flow_key->l4_src = temp1;
    return bpf_map_update_elem(&flow_ctx_table, flow_key, flow_key, BPF_ANY);
}

inline bool check_key(struct flow_ctx_table_key *flow_key)
{
    struct flow_ctx_table_key *value;
    value = bpf_map_lookup_elem(&flow_ctx_table, flow_key);
    if (value)
    {
        return true;
    }
    return false;
}

SEC("xdp")
int fw_kfunc(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE_ARRAY(main);

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct flow_ctx_table_key flow_key = {0};

    struct ethhdr *ethernet;
    struct iphdr *ip;
    struct udphdr *l4;

    int ingress_ifindex;
    __u64 nh_off = 0;
    /*  remember, to see printk
     * sudo cat /sys/kernel/debug/tracing/trace_pipe
     */
    // bpf_printk("I'm in the pipeline\n");

    ethernet = data;
    nh_off = sizeof(*ethernet);
    if (data + nh_off > data_end)
        goto EOP;

    ingress_ifindex = ctx->ingress_ifindex;
    if (!bpf_ntohs(ethernet->h_proto))
        goto EOP;

    // bpf_printk("I'm eth\n");
    switch (bpf_ntohs(ethernet->h_proto))
    {
    case ETH_P_IP:
        goto ip;
    default:
        goto EOP;
    }

ip: {
    // bpf_printk("I'm ip\n");

    ip = data + nh_off;
    nh_off += sizeof(*ip);
    if (data + nh_off > data_end)
        goto EOP;

    switch (ip->protocol)
    {
    case IPPROTO_TCP:
        goto l4;
    case IPPROTO_UDP:
        goto l4;
    default:
        goto EOP;
    }
}

l4: {
    // bpf_printk("I'm l4\n");
    l4 = data + nh_off;
    nh_off += sizeof(*l4);
    if (data + nh_off > data_end)
        goto EOP;
}

    // bpf_printk("extracting flow key ... \n");
    /* flow key */
    flow_key.ip_proto = ip->protocol;

    flow_key.ip_src = ip->saddr;
    flow_key.ip_dst = ip->daddr;
    flow_key.l4_src = l4->source;
    flow_key.l4_dst = l4->dest;

    if (is_internal_ip(&flow_key))
    {
        // add key to the table
        insert_key(&flow_key);
        // bpf_printk("err");
        // bpf_printk("insert key\n");
        BPF_MYKPERF_END_TRACE_ARRAY(main);
        return XDP_TX;
    }
    else if (is_external_ip(&flow_key))
    {
        // check if the key is available inside the map
        if (check_key(&flow_key))
        {
            // bpf_printk("key found\n");
            BPF_MYKPERF_END_TRACE_ARRAY(main);
            return XDP_TX;
        }
        else
        {
            BPF_MYKPERF_END_TRACE_ARRAY(main);
            return XDP_DROP;
        }
    }
EOP:
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
