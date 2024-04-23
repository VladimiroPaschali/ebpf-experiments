#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <xdpmychardev.h>

BPF_MYKPERF_INIT_TRACE();

SEC("xdp") int drop_sr(struct xdp_md *ctx)
{

    BPF_MYKPERF_START_TRACE_ARRAY_SAMPLED(main);

    BPF_MYKPERF_END_TRACE_ARRAY(main, 0);


    COUNT_RUN;
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
