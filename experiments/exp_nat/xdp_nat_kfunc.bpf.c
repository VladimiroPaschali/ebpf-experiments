/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 * This is main balancer's application code
 */

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <stdbool.h>
#include "nat_consts.h"
#include "nat_helpers.h"
#include "nat_structs.h"
#include "nat_maps.h"
#include "nat_pckt_parsing.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ptrace.h>

#include "mykperf_module.h"

BPF_MYKPERF_INIT_TRACE();
DEFINE_SECTIONS("main");

int free_port_p = 10000;

__attribute__((__always_inline__)) static inline void connection_table_lookup(struct binding_definition **bind,
                                                                              struct packet_description *pckt,
                                                                              void *map)
{

    void *p = bpf_map_lookup_elem(map, &pckt->flow); // XXX MAPPA

    if (!p)
    {
        *bind = NULL;
    }

    *bind = p;
}

__attribute__((__always_inline__)) static inline bool process_l3_headers(struct packet_description *pckt,
                                                                         struct iphdr *iph)
{
    // ihl contains len of ipv4 header in 32bit words
    if (iph->ihl != 5)
    {
        // if len of ipv4 hdr is not equal to 20bytes that means that header
        // contains ip options, and we dont support em
        return XDP_DROP;
    }

    if (iph->frag_off & PCKT_FRAGMENTED)
    {
        // we drop fragmented packets.
        return XDP_DROP;
    }
    pckt->flow.src = iph->saddr;
    pckt->flow.dst = iph->daddr;

    return 0;
}

__attribute__((__always_inline__)) static inline int nat_parse_tcp(void *data, void *data_end,
                                                                   struct packet_description *pckt)
{

    struct tcphdr *tcp;
    tcp = data;

    if (tcp + 1 > data_end)
    {
        return XDP_DROP;
    }

    /*if (tcp->syn) {
      pckt->flags |= F_SYN_SET;
    }*/

    pckt->flow.port16[0] = tcp->source;
    pckt->flow.port16[1] = tcp->dest;
    return 0;
}

__attribute__((__always_inline__)) static inline bool nat_parse_udp(void *data, void *data_end,
                                                                    struct packet_description *pckt)
{

    struct udphdr *udp;
    udp = data;

    if (udp + 1 > data_end)
    {
        return XDP_DROP;
    }

    pckt->flow.port16[0] = udp->source;
    pckt->flow.port16[1] = udp->dest;
    return 0;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

__attribute__((__always_inline__)) static inline int process_packet(void *data, __u64 off, void *data_end,
                                                                    struct xdp_md *xdp)
{
    struct binding_definition *nat_binding_entry = NULL;
    struct packet_description pckt = {}, ret_pckt = {};
    __u16 new_ports[2];
    __sum16 *csum_p;
    __u32 csum_off;
    __u32 l4_hdr_end;
    __be32 *new_addr_pck_pointer = NULL;
    __be32 new_addr;
    __u8 protocol;
    int ret;
    struct iphdr *ip = data + sizeof(struct eth_hdr);
    if (ip + 1 > data_end)
    {
        return XDP_DROP;
    }

    protocol = ip->protocol;
    pckt.flow.proto = protocol;

    if ((ret = process_l3_headers(&pckt, ip)) != 0)
    {
        return ret;
    }

    void *l4 = (void *)ip + 20;

    if (protocol == IPPROTO_TCP)
    {
        if ((ret = nat_parse_tcp(l4, data_end, &pckt)))
        {
            return ret;
        }
    }
    else if (protocol == IPPROTO_UDP)
    {
        if ((ret = nat_parse_udp(l4, data_end, &pckt)))
        {
            return ret;
        }
    }
    else
    {
        return XDP_DROP;
    }

    // BPF_MYKPERF_START_TRACE_ARRAY(main);

    /*if ((protocol == IPPROTO_UDP) || !(pckt.flags & F_SYN_SET)) {*/
    connection_table_lookup(&nat_binding_entry, &pckt, &nat_binding_table);
    //}

    if (pckt.flow.dst != NAT_EXTERNAL_ADDRESS)
    {
        if (!nat_binding_entry)
        {
            struct binding_definition new_binding_value = {};

            new_binding_value.addr = NAT_EXTERNAL_ADDRESS;
            new_binding_value.port = free_port_p;

            if (bpf_map_update_elem(&nat_binding_table, &pckt.flow, &new_binding_value, 0))
            {

                return XDP_DROP;
            }
            // insert entry for reply packets
            ret_pckt.flow.src = pckt.flow.dst;
            ret_pckt.flow.dst = NAT_EXTERNAL_ADDRESS;
            ret_pckt.flow.port16[0] = pckt.flow.port16[1];
            ret_pckt.flow.port16[1] = free_port_p;
            ret_pckt.flow.proto = pckt.flow.proto;

            new_binding_value.addr = pckt.flow.src;
            new_binding_value.port = pckt.flow.port16[0];

            if (bpf_map_update_elem(&nat_binding_table, &ret_pckt.flow, &new_binding_value, 0))
            {

                return XDP_DROP;
            }

            new_ports[0] = free_port_p;
            free_port_p++;
        }
        else
        {

            new_ports[0] = nat_binding_entry->port;
        }

        new_addr = NAT_EXTERNAL_ADDRESS;
        new_addr_pck_pointer = &ip->saddr;
        new_ports[1] = ((__u16 *)l4)[1];
    }
    else
    {
        if (!nat_binding_entry)
        {

            return XDP_DROP;
        }

        new_ports[0] = ((__u16 *)l4)[0];
        new_ports[1] = nat_binding_entry->port;
        new_addr = nat_binding_entry->addr;
        new_addr_pck_pointer = &ip->daddr;
    }

    // recompute ip csum
    ip->check =
        csum_fold_helper(bpf_csum_diff(new_addr_pck_pointer, sizeof(__be32), &new_addr, sizeof(__be32), ~(ip->check)));

    // recompute l4 csum
    if (ip->protocol == IPPROTO_UDP)
    {
        csum_off = 40;
        l4_hdr_end = 2;
    }
    else if (ip->protocol == IPPROTO_TCP)
    {
        csum_off = 50;
        l4_hdr_end = 4;
    }
    else
    {
        return XDP_DROP;
    }

    csum_p = (__sum16 *)((__u8 *)data + csum_off);

    if (data + csum_off + l4_hdr_end > data_end)
    {
        return XDP_DROP;
    }

    *csum_p = csum_fold_helper(
        bpf_csum_diff((__be32 *)l4, sizeof(__be32), (__be32 *)new_ports, sizeof(__be32), ~(*(__u16 *)csum_p)));

    *csum_p = csum_fold_helper(
        bpf_csum_diff(new_addr_pck_pointer, sizeof(__be32), &new_addr, sizeof(__be32), ~(*(__u16 *)csum_p)));

    // change source port
    __builtin_memcpy(l4, &new_ports[0], 4);
    __builtin_memcpy((__u8 *)new_addr_pck_pointer, &new_addr, 4);

    return XDP_TX;
}

SEC("xdp")
int xdp_nat_kfunc(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE_ARRAY(main);

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth = data;
    __u32 eth_proto;
    __u32 nh_off;
    nh_off = sizeof(struct eth_hdr);

    if (data + nh_off > data_end)
    {
        // bogus packet, len less than minimum ethernet frame size
        return XDP_DROP;
    }

    eth_proto = eth->eth_proto;
    if (eth_proto == BE_ETH_P_IP)
    {
        int ret = process_packet(data, nh_off, data_end, ctx); // moved here to allow profiling
        BPF_MYKPERF_END_TRACE_ARRAY(main);
        return ret;
    }
    else
    {
        // BPF_MYKPERF_END_TRACE_ARRAY(main);
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
