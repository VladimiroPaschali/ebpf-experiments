#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

// prog array
struct
{
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} bpf_prog_info SEC(".maps");

SEC("xdp")
int xdp_1(struct xdp_md *ctx)
{
    bpf_printk("sopno il parent");
    __u64 err = 0;
    err = bpf_tail_call(ctx, &bpf_prog_info, 0);
    if (err < 0)
    {
        bpf_printk("error tail call");
    }

    bpf_printk("aaaaaaaaaaa");
    return XDP_PASS;
}

SEC("xdp")
int xdp_2(struct xdp_md *ctx)
{
    bpf_printk("sono il child");
    return XDP_PASS;
}

// license
char _license[] SEC("license") = "GPL";