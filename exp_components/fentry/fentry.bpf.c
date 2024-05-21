#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("fentry/XXX")
int BPF_PROG(fentry)
{
    return 0;
}

char _license[] SEC("license") = "GPL";
