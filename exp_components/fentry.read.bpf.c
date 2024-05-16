#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1);
} perf_map SEC(".maps");

SEC("fentry/XXX")
int BPF_PROG(fentry_XXX)
{
    __u32 cpu = bpf_get_smp_processor_id();
    struct bpf_perf_event_value value = {0};
    bpf_perf_event_read_value(&perf_map, cpu, &value, sizeof(value));
    return 0;
}

// SEC("fexit/xdp")
// int BPF_PROG(fexit_2) {
//	bpf_printk("fexit 2");
//	return 0;
// }
//
char _license[] SEC("license") = "GPL";
