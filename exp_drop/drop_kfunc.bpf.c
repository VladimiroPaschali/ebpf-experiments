#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
}pkt_counter SEC(".maps") ;


__u64 bpf_mykperf_read_rdpmc(__u8 counter) __ksym;

SEC("xdp") int drop_kfunc(struct xdp_md *ctx)
{
    volatile __u64 x = bpf_mykperf_read_rdpmc(0);

    __u32 key = 0;
    __u32 *counter;

    
    return XDP_DROP;

    volatile __u64 y = bpf_mykperf_read_rdpmc(0);


    counter = bpf_map_lookup_elem(&pkt_counter, &key);
    if (counter) {
        (*counter)++;

    }
}

char _license[] SEC("license") = "GPL";