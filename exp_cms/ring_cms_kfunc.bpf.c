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

#define UNLIKELY(x) __builtin_expect(!!(x), 0)

__u64 bpf_mykperf_read_rdpmc(__u8 counter__k) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps") ;

static inline int hash(char str[15]) {
	int hash = 5381;
	int c;
	int i = 0;

	while (i < 14) {
		i++;
		c = str[i];
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
}
 
char key[15];
int counter = 0;
struct event *e;

//static long loop_callback(__u32 index, struct xdp_md* ctx) {
//    	__u32 row_index = 0;
//    	__u32 row_index_old = 0;
//	__u32* val;
//	__u32 new_val = 0;
//	// update key
//	key[13] = index;
//
//	struct event *e;
//
//	e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
//	if (!e)
// 		return 0;
//
//	row_index = hash(key);
//	row_index = (uint)row_index % (uint)CMS_SIZE;
//	e->row_index = (__u16)index;
//	e->hash = row_index;
//	bpf_ringbuf_submit(e,BPF_RB_FORCE_WAKEUP);
//	return 0;
//}

SEC("xdp")
int ring_cms_kfunc(struct xdp_md *ctx) {
    __u64 reg_count = bpf_mykperf_read_rdpmc(1) ;
    counter++;
    //bpf_printk("Counter %d", counter);
    //bpf_printk("Counter %d", counter);
    void* data = (void*)(long)(ctx->data);
    void* data_end = (void*)(long)(ctx->data_end);
    struct ethhdr* eth_hdr = data;
    struct iphdr* ip_hdr;
    struct tcphdr* tcp_hdr;
    struct udphdr* udp_hdr;
    
    uint parse = 0;
    __u32* val;
    __u32 new_val;
        new_val = 1;
        
    __u32 row_index = 0;
    __u32 row_index_old = 0;
    __u16 protocol = 0;
    __u32 src_ip = 0;
    __u32 dst_ip = 0;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    
    if (data + sizeof(struct ethhdr) < (void*)(long)ctx->data_end) {
    	protocol = eth_hdr->h_proto;
    	if (protocol == htons(ETH_P_IP) ) {
    		ip_hdr = (void*)(long)(ctx->data+sizeof(struct ethhdr));
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) >=  data_end) 
			goto end;
    		src_ip = ip_hdr->saddr;
    		dst_ip = ip_hdr->daddr;
    		if (ip_hdr->protocol == IPPROTO_TCP) {
    			tcp_hdr = (void*)(long)(ctx->data+sizeof(struct ethhdr)+sizeof(struct iphdr));
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) >= data_end)
				goto end;
    			src_port = tcp_hdr->source;
    			dst_port = tcp_hdr->dest;
    			protocol = IPPROTO_TCP;
    	    		row_index = src_ip+dst_ip+dst_port+src_port+protocol;
    	    		parse = 1;
			*((__u32*)(&key[0])) = src_ip;
			*((__u32*)(&key[4])) = dst_ip;
			*((__u16*)(&key[8])) = src_port;
			*((__u16*)(&key[10])) = src_port;
			*((__u8*)(&key[12])) = IPPROTO_TCP;
    		}
    		else if (ip_hdr->protocol == IPPROTO_UDP) {
    			udp_hdr = (void*)(long)(ctx->data+sizeof(struct ethhdr)+sizeof(struct iphdr));
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) >= data_end)
				goto end;
    			src_port = udp_hdr->source;
    			dst_port = udp_hdr->dest;
    			protocol = IPPROTO_UDP;
    	    		row_index = src_ip+dst_ip+dst_port+src_port+protocol;
			*((__u32*)(&key[0])) = src_ip;
			*((__u32*)(&key[4])) = dst_ip;
			*((__u16*)(&key[8])) = src_port;
			*((__u16*)(&key[10])) = src_port;
			*((__u8*)(&key[12])) = IPPROTO_UDP;
    	    		parse = 1; 
    		} 
    	}
    } 
    key[14] = 0;
    if (parse) {
	    //bpf_loop(CMS_ROWS, &loop_callback, &ctx, 0) ;
	    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	    if (UNLIKELY(!e)) {
		    return XDP_PASS;
	    }
	    e->hash = 0;
	    for (int i = 0; i < CMS_ROWS; i++) {
    		key[13] = i;
	    	row_index = hash(key);
		e->hash |= (((__u64)(row_index & 0xFFFF)) << 16*i);
	    }

	    bpf_ringbuf_submit(e,BPF_RB_NO_WAKEUP);
    }
	//volatile __u64 x = bpf_mykperf_read_rdpmc(0);

    
end:
    reg_count = bpf_mykperf_read_rdpmc(1) -reg_count; 
    bpf_printk("Counter %d", reg_count);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
