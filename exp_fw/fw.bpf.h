#ifndef FW_H
#define FW_H

#define A_PORT 6
#define B_PORT 7

#include <linux/types.h>

#define START_PRIVATE_IP 0xC0A80001
#define END_PRIVATE_IP 0xC0A800FE

struct cms
{
    __u32 data[4][32];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_ctx_table_key);
    __type(value, struct flow_ctx_table_key);
} flow_ctx_table SEC(".maps");

struct flow_ctx_table_key
{
    /*per-application */
    __u16 ip_proto;
    __u16 l4_src;
    __u16 l4_dst;
    __u32 ip_src;
    __u32 ip_dst;
};

struct flow_ctx_table_leaf
{
    __u8 out_port;
    __u16 in_port;
    //	flow_register_t flow_reg;
};

inline __u8 is_internal_ip(struct flow_ctx_table_key *key)
{
    //__be32 asd = START_PRIVATE_IP;
    // bpf_printk("%pI4 --- %pI4", &key->ip_src, &asd);
    return key->ip_src >= bpf_htonl(START_PRIVATE_IP) && key->ip_src <= bpf_htonl(END_PRIVATE_IP);
}

inline __u8 is_external_ip(struct flow_ctx_table_key *key)
{
    return !is_internal_ip(key);
}

#endif /* FW_H */
