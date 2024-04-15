#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
}pkt_counter SEC(".maps") ;

SEC("xdp") int drop_map(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u32 *counter;

    counter = bpf_map_lookup_elem(&pkt_counter, &key);
    if (counter) {
        (*counter)++;
        // bpf_printk("pacchetto");

    }

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";