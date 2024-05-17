#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

__u64 bpf_mykperf__rdpmc(__u64 counter) __ksym;

SEC("xdp")
int kfunc(struct xdp_md *ctx)
{
    __u64 start = bpf_mykperf__rdpmc(0);

    __u64 end = bpf_mykperf__rdpmc(0) - start;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";