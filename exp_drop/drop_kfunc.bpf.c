#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <mykperf_module.h>




BPF_MYKPERF_INIT_TRACE();

SEC("xdp") int drop_kfunc(struct xdp_md *ctx)
{
    BPF_MYKPERF_START_TRACE_ARRAY(main, 0);

    
    BPF_MYKPERF_END_TRACE_ARRAY(main, 0, 0);

    return XDP_DROP;    
}

char _license[] SEC("license") = "GPL";