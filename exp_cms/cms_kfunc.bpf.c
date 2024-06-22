#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include "cms.h"
#include <asm/types.h>

#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE();
DEFINE_SECTIONS("main");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cms);
} cms_map SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, __u32);
// 	__type(value, __u32);
// } pkt_counter SEC(".maps");

static inline int hash(char str[15])
{
    int hash = 5381;
    int c;
    int i = 0;

    while (i < 14)
    {
        i++;
        c = str[i];
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }

    return hash;
}

static __always_inline uint32_t djb2_hash(char str[15])
{
    uint32_t hash = 5381;
    int c;
    int len = 15;
    int i;

    for (i = 0; i < 15; i++)
    {
        c = str[i];
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

static __always_inline uint32_t jenkins_hash(char key[15])
{
    uint32_t hash, i;
    for (hash = i = 0; i < 15; ++i)
    {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

SEC("xdp")
int cms_kfunc(struct xdp_md *ctx)
{

    // BPF_MYKPERF_START_TRACE_ARRAY(main);
    BPF_MYPERF_START_TRACE_MULTIPLEXED(main);

    char key[15];
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);
    struct ethhdr *eth_hdr = data;
    struct iphdr *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;

    uint parse = 0;
    __u32 *val;
    __u32 new_val;
    new_val = 1;

    __u32 row_index = 0;
    __u32 row_index_old = 0;
    __u16 protocol = 0;
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (data + sizeof(struct ethhdr) < (void *)(long)ctx->data_end)
    {
        protocol = eth_hdr->h_proto;
        if (protocol == htons(ETH_P_IP))
        {
            ip_hdr = (void *)(long)(ctx->data + sizeof(struct ethhdr));
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) >= data_end)
                goto end;
            src_ip = ip_hdr->saddr;
            dst_ip = ip_hdr->daddr;
            if (ip_hdr->protocol == IPPROTO_TCP)
            {
                tcp_hdr = (void *)(long)(ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) >= data_end)
                    goto end;
                src_port = tcp_hdr->source;
                dst_port = tcp_hdr->dest;
                protocol = IPPROTO_TCP;
                row_index = src_ip + dst_ip + dst_port + src_port + protocol;
                parse = 1;
                *((__u32 *)(&key[0])) = src_ip;
                *((__u32 *)(&key[4])) = dst_ip;
                *((__u16 *)(&key[8])) = src_port;
                *((__u16 *)(&key[10])) = src_port;
                *((__u8 *)(&key[12])) = IPPROTO_TCP;
            }
            else if (ip_hdr->protocol == IPPROTO_UDP)
            {
                udp_hdr = (void *)(long)(ctx->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
                if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) >= data_end)
                    goto end;
                src_port = udp_hdr->source;
                dst_port = udp_hdr->dest;
                protocol = IPPROTO_UDP;
                row_index = src_ip + dst_ip + dst_port + src_port + protocol;
                *((__u32 *)(&key[0])) = src_ip;
                *((__u32 *)(&key[4])) = dst_ip;
                *((__u16 *)(&key[8])) = src_port;
                *((__u16 *)(&key[10])) = src_port;
                *((__u8 *)(&key[12])) = IPPROTO_UDP;
                parse = 1;
            }
        }
    }
    key[14] = 0;
    if (parse)
    {
        int addr = 0;
        struct cms *cms = bpf_map_lookup_elem(&cms_map, &addr);
        if (cms == NULL)
            goto end;
        for (int i = 0; i < CMS_ROWS; i++)
        {
            // update key
            key[13] = i;
            // get inner map
            // BPF_MYKPERF_START_TRACE_ARRAY(main);
            // row_index = djb2_hash(key);
            // BPF_MYKPERF_END_TRACE_ARRAY(main);
            row_index = djb2_hash(key);
            // row_index = jenkins_hash(key);
            row_index = (uint)row_index % (uint)CMS_SIZE;
            // bpf_printk("old val: %u", cms->count[i][row_index]);
            cms->count[i][row_index]++;
            // bpf_printk("new val %u", cms->count[i][row_index]);
        }
    }
    // volatile __u64 x = bpf_mykperf_read_rdpmc(0);

end:
    // BPF_MYKPERF_END_TRACE_ARRAY(main);
    BPF_MYPERF_END_TRACE_MULTIPLEXED(main);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
