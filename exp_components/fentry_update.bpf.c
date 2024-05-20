#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1);
} perf_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_perf_event_value));

    __uint(max_entries, 1);
} update_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct bpf_perf_event_value));
    __uint(max_entries, 1);
} acc_map SEC(".maps");

static inline void fexit_update_maps(__u32 id, struct bpf_perf_event_value *after)
{
    struct bpf_perf_event_value *before, diff;

    before = bpf_map_lookup_elem(&update_map, &id);
    /* only account samples with a valid fentry_reading */
    if (before && before->counter)
    {
        struct bpf_perf_event_value *accum;

        diff.counter = after->counter - before->counter;
        diff.enabled = after->enabled - before->enabled;
        diff.running = after->running - before->running;

        accum = bpf_map_lookup_elem(&acc_map, &id);
        if (accum)
        {
            accum->counter += diff.counter;
            accum->enabled += diff.enabled;
            accum->running += diff.running;
        }
    }
}

SEC("fentry/XXX")
int BPF_PROG(fentry_update)
{
    __u32 cpu = bpf_get_smp_processor_id();
    struct bpf_perf_event_value value = {0};
    bpf_perf_event_read_value(&perf_map, cpu, &value, sizeof(value));

    fexit_update_maps(cpu, &value);
    return 0;
}

char _license[] SEC("license") = "GPL";
