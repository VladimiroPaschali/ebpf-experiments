#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__u64 run_cnt = 0;

SEC("xdp")
int drop(struct xdp_md *ctx)
{
    __sync_fetch_and_add(&run_cnt, 1);
    return XDP_DROP;
}
char _license[] SEC("license") = "GPL";
