#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <mykperf_module.h>

BPF_MYKPERF_INIT_TRACE();
DEFINE_SECTIONS("main");

SEC("xdp") int drop_kfunc(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE_ARRAY(main);

    BPF_MYKPERF_END_TRACE_ARRAY(main);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
