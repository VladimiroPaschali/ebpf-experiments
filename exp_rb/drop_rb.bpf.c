#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "mykperf_module.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024); // may need to be increased
} ring_out SEC(".maps");

struct record
{
    __u64 value;
    __u64 count;
    __u64 counter;
    char name[16];
} __attribute__((aligned(64)));

SEC("xdp") int drop_rb(struct xdp_md *ctx)
{
    struct record *rec = {0};
/*     rec->value = 42;
    rec->count = 100;
    rec->counter = 0;
    strcpy(rec->name, "test"); */

    rec = bpf_ringbuf_reserve(&ring_out, sizeof(*rec), 0);
    if (!rec)
    {
        return XDP_DROP;
    }

    bpf_ringbuf_submit(rec, 0);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
