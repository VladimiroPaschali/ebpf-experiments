#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp") int drop(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";