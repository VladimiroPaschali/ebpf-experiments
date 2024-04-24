#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} counts SEC(".maps");

SEC("fexit/*")
int BPF_PROG(fexit_XXX, int ret)
{
    if (ret)
    {
        bpf_printk("fexit_XXX: %d\n", ret);
        ret = 0;
    }
    return 0;
}

/* SEC("fexit/*")
int BPF_PROG(fexit_XXX)
{
    __u32 zero = 0;
    __u64 *count = bpf_map_lookup_elem(&counts, &zero);
    if (count)
        *count += 1;
    return 0;
} */

char _license[] SEC("license") = "GPL";