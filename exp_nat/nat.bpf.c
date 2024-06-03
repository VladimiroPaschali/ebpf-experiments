/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 * This is main balancer's application code
 */

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ptrace.h>

int free_port_p = 10000;

#define INTERNAL_IP_START 0xc0a80001
#define INTERNAL_IP_END   0xc0a800fe

#define EXTERNAL_IP_START 0x0a000001
#define EXTERNAL_IP_END   0x0a0000fe

#define NAT_IP            0x0b000001


struct flow {
    __be32 src;
    __be32 dst;
    __be16 port16[2];
    __u8 proto;
};

struct binding_definition {
    __be32 addr;
    __be16 port;
};


/* key: flow with internal ip and port and external ip and port
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow);
	__type(value, struct binding_definition);
	__uint(max_entries, 1024);
} internal_external_mapping SEC(".maps"); 

/* key: flow with external ip and port and nat ip and port
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct flow);
	__type(value, struct binding_definition);
	__uint(max_entries, 1024);
} external_nat_mapping SEC(".maps");

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
    struct flow pckt = {}, ret_pckt = {};
    __u16 new_ports[2];
    __sum16 *csum_p;
    __u32 csum_off;
    __u32 l4_hdr_end;
    __be32 *new_addr_pck_pointer = NULL;
    __be32 new_addr;
    __u8 protocol;
    int ret;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if (ip + 1 > data_end)
    {
        return XDP_DROP;
    }

    protocol = ip->protocol;
    pckt.proto = protocol;
    pckt.src = ip->saddr;
    pckt.dst = ip->daddr;


    // bpf_printk("l3\n");
    if (protocol == IPPROTO_TCP)
    {
	    if (tcp + 1 > data_end)
	    {
	        return XDP_DROP;
	    }
	    pckt.port16[0] = tcp->source;
	    pckt.port16[1] = tcp->dest;
    }
    else 
    {
	return XDP_PASS;
    }

    /* check if packet is internal or external */
    // packet coming from internal network
    if (pckt.dst >= EXTERNAL_IP_START && pckt.dst <= EXTERNAL_IP_END)
    {
	// bpf_printk("external packet\n");
	nat_binding_entry = bpf_map_lookup_elem(&internal_external_mapping, &pckt);
	if (!nat_binding_entry) {
		// bpf_printk("binding entry not found\n");
		// bpf_printk("nat addr %d port %d\n", nat_binding_entry->addr, nat_binding_entry->port);
		// bpf_printk("internal addr %d port %d\n", pckt.src, pckt.port16[0]);
		// bpf_printk("external addr %d port %d\n", pckt.dst, pckt.port16[1]);
		// bpf_printk("nat addr %d port %d\n", nat_binding_entry->addr, nat_binding_entry->port);
		// create new entry
		struct binding_definition new_binding_value = {};
		new_binding_value.addr = bpf_ntohl(NAT_IP);
		new_binding_value.port = free_port_p;
		if (bpf_map_update_elem(&internal_external_mapping, &pckt, &new_binding_value, 0))
		{
			// bpf_printk("error instering nat binding\n");
			return XDP_DROP;
		}

		// insert entry for external_nat_mapping
		struct flow new_flow = {};
		new_flow.src = pckt.dst;
		new_flow.dst = bpf_ntohl(NAT_IP);
		new_flow.port16[0] = pckt.port16[1];
		new_flow.port16[1] = free_port_p;
		new_flow.proto = pckt.proto;
		new_binding_value.addr = pckt.src;
		new_binding_value.port = pckt.port16[0];

		if (bpf_map_update_elem(&external_nat_mapping, &new_flow, &new_binding_value, 0))
		{
			// bpf_printk("error instering nat binding\n");
			return XDP_DROP;
		}

		// increase port number
		free_port_p++;
		nat_binding_entry = &new_binding_value;

	} 
	// modify packet
	ip->saddr = bpf_htonl(nat_binding_entry->addr);
	tcp->source = bpf_htons(nat_binding_entry->port);
    }
    else if (pckt.dst == bpf_ntohl(NAT_IP))
    {
	// bpf_printk("external packet\n");
	nat_binding_entry = bpf_map_lookup_elem(&external_nat_mapping, &pckt);
	if (!nat_binding_entry) {
		// bpf_printk("binding entry not found\n");
		return XDP_DROP;
	}
	// modify packet
	ip->daddr = bpf_htonl(nat_binding_entry->addr);
	tcp->dest = bpf_htons(nat_binding_entry->port);
    }
    else
    {
	// bpf_printk("unknown packet\n");
	return XDP_DROP;
    }




    // recompute ip csum
    ip->check =
        csum_fold_helper(bpf_csum_diff(new_addr_pck_pointer, sizeof(__be32), &new_addr, sizeof(__be32), ~(ip->check)));

    csum_off = 50;
    l4_hdr_end = 4;

    csum_p = (__sum16 *)((__u8 *)data + csum_off);

    if (data + csum_off + l4_hdr_end > data_end)
    {
        return XDP_DROP;
    }

    *csum_p = csum_fold_helper(
        bpf_csum_diff((__be32 *)tcp, sizeof(__be32), (__be32 *)new_ports, sizeof(__be32), ~(*(__u16 *)csum_p)));

    *csum_p = csum_fold_helper(
        bpf_csum_diff(new_addr_pck_pointer, sizeof(__be32), &new_addr, sizeof(__be32), ~(*(__u16 *)csum_p)));

    return XDP_TX;
}

SEC("xdp")
int xdp_nat(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 eth_proto;
    __u32 nh_off;
    nh_off = sizeof(struct ethhdr);

    // bpf_printk("GOT PACKET\n");
    if (data + nh_off > data_end)
    {
        // bogus packet, len less than minimum ethernet frame size
        return XDP_DROP;
    }

    eth_proto = eth->h_proto;
    if (eth_proto == bpf_htons(ETH_P_IP))
    {
        return process_packet(data, nh_off, data_end, ctx);
    }
    else
    {
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
