#ifndef FW_H
#define FW_H

#define A_PORT  6
#define B_PORT 7


#include <linux/types.h>


#define START_PRIVATE_IP 0xC0A80000
#define END_PRIVATE_IP 0xC0A800FF


struct flow_ctx_table_key {
	/*per-application */
	__u16 ip_proto;
	__u16 l4_src;
	__u16 l4_dst;
	__u32 ip_src;
	__u32 ip_dst;

};

struct flow_ctx_table_leaf {
	__u8 out_port;
	__u16 in_port;
//	flow_register_t flow_reg;
};


inline __u8 is_internal_ip(struct flow_ctx_table_key* key) {
	return key->ip_src >= START_PRIVATE_IP && key->ip_src <= END_PRIVATE_IP;
}

inline __u8 is_external_ip(struct flow_ctx_table_key* key) {
	return !is_internal_ip(key);
}

#endif /* FW_H */
