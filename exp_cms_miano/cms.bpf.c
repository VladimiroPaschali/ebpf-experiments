/*
 * Copyright 2021 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
//#include <netinet/in.h>
#include <stdint.h>

//#include <uapi/linux/bpf.h>
//#include <uapi/linux/filter.h>
//#include <uapi/linux/icmp.h>
//#include <uapi/linux/if_arp.h>
//#include <uapi/linux/if_ether.h>
//#include <uapi/linux/if_packet.h>
//#include <uapi/linux/in.h>
//#include <uapi/linux/ip.h>
//#include <uapi/linux/pkt_cls.h>
//#include <uapi/linux/tcp.h>
//#include <uapi/linux/udp.h>
//#include <linux/if_vlan.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "fasthash.h"

/* ANDREA */
// giving program all the defs that are passed through bcc
#define _OUTPUT_INTERFACE_IFINDEX 0
#define _CS_ROWS 4
#define _CS_COLUMNS 1048576

#define BPF_PERCPU_ARRAY(name, entry, count) \
struct { \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
    __uint(max_entries, (count)); \
    __type(key, __u32); \
    __type(value, (entry)); \
} (name) SEC(".maps"); 

#define _SEED_HASHFN 77
#define _COUNT_PACKETS
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};
#define htons(x) (((((unsigned short)(x) & 0xFF00) >> 8) | \
			                  (((unsigned short)(x) & 0x00FF) << 8)))

/* END ANDREA */
#define HASHFN_N _CS_ROWS
#define COLUMNS _CS_COLUMNS

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct countmin {
	__u32 values[HASHFN_N][COLUMNS];
};

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));

struct pkt_md {
#ifdef _COUNT_PACKETS
  uint64_t drop_cnt;
#else
  uint64_t bytes_cnt;
#endif
};

struct { 
    //__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1); 
    __type(key, __u32); 
    __type(value, struct pkt_md); 
} dropcnt SEC(".maps"); 

struct { 
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1); 
    __type(key, __u32); 
    __type(value, struct countmin); 
} countmin SEC(".maps"); 
//BPF_PERCPU_ARRAY(dropcnt, (struct pkt_md), 1);
//BPF_ARRAY(countmin, struct countmin, 1);

static void FORCE_INLINE countmin_add(struct countmin *cm, void *element, __u64 len)
{
	// Calculate just a single hash and re-use it to update and query the sketch
    uint64_t h = fasthash64(element, len, _SEED_HASHFN);

    uint16_t hashes[4];
    hashes[0] =  (h & 0xFFFF);
    hashes[1] =  h  >> 16 & 0xFFFF;
    hashes[2] =  h  >> 32 & 0xFFFF;
    hashes[3] =  h  >> 48 & 0xFFFF;

	_Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

	for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
		__u32 target_idx = hashes[i] & (COLUMNS - 1);
        NO_TEAR_ADD(cm->values[i][target_idx], 1);
	}

	return;
}

SEC("xdp")
int cms(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    uint64_t nh_off = 0;
    struct eth_hdr *eth = data;
    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        goto DROP;

    uint16_t h_proto = eth->proto;

    // parse double vlans
    #pragma unroll
    for (int i=0; i < 2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;
            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                goto DROP;
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    switch (h_proto) {
        case htons(ETH_P_IP):
            break;
        default:
            return XDP_PASS;
    }

    struct pkt_5tuple pkt;

    struct iphdr *ip = data + nh_off;
    if ((void*)&ip[1] > data_end)
        goto DROP;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;

    switch (ip->protocol) {
        case IPPROTO_TCP: {
            struct tcp_hdr *tcp = NULL;
            tcp = data + nh_off + sizeof(*ip);
            if (data + nh_off + sizeof(*ip) + sizeof(*tcp) > data_end)
                goto DROP;               
            pkt.src_port = tcp->source;
            pkt.dst_port = tcp->dest;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = NULL;
            udp = data + nh_off + sizeof(*ip);
            if (data + nh_off + sizeof(*ip) + sizeof(*udp) > data_end)
                goto DROP; 
            pkt.src_port = udp->source;
            pkt.dst_port = udp->dest;
            break;
        }
        default:
            goto DROP;
    }

    uint32_t zero = 0;
    struct countmin *cm;

    cm = bpf_map_lookup_elem(&countmin,&zero);
    //cm = countmin.lookup(&zero);

    if (!cm) {
        bpf_printk("Invalid entry in the countmin sketch");
        goto DROP;
    }

    countmin_add(cm, &pkt, sizeof(pkt));

    struct pkt_md *md;
    uint32_t index = 0;
    md = bpf_map_lookup_elem(&dropcnt,&index);
    //md = dropcnt.lookup(&index);
    if (md) {
	//bpf_printk("updating cms");
#ifdef _COUNT_PACKETS 
        NO_TEAR_INC(md->drop_cnt);
#else
        uint16_t pkt_len = (uint16_t)(data_end - data);
        NO_TEAR_ADD(md->bytes_cnt, pkt_len);
#endif
    }

#if _ACTION_DROP
    return XDP_DROP;
#else
    return bpf_redirect(_OUTPUT_INTERFACE_IFINDEX, 0);
#endif

DROP:;
    bpf_printk("Error. Dropping packet\n");
    return XDP_DROP;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
