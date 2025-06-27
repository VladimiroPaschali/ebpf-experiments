#include "mykperf_module.h"
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u32);
  __uint(max_entries, 1);
} prog1_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
  __uint(max_entries, 100);
} map_tail SEC(".maps");

SEC("xdp")
int tail(struct xdp_md *ctx) {
  int err;
  bpf_printk("This is the 0 program\n");
  

  bpf_tail_call(ctx, &map_tail, 1);
  // if a bpf program called using tail call not return to the main caller, in this case prog0
  // the following code will not be executed, and the stat about this section will be 0
  bpf_printk("This is the 0 program after tail call\n");
  return XDP_DROP;
}

SEC("xdp")
int prog1(struct xdp_md *ctx) {

  __u32 key = 0;
  __u32 *value = bpf_map_lookup_elem(&prog1_map, &key);
  if (!value) {
    bpf_printk("Failed to lookup element\n");
    return XDP_DROP;
  } else {
    bpf_printk("Value: %u\n", *value);
    *value += 1;
  }
  bpf_printk("This is the 1 program\n");

  bpf_tail_call(ctx, &map_tail, 2);

  return XDP_DROP;
}

SEC("xdp")
int prog2(struct xdp_md *ctx) {

  bpf_printk("This is the 2 program\n");

  bpf_tail_call(ctx, &map_tail, 0);

  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
