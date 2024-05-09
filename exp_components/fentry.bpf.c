#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("fentry/xdp")
int BPF_PROG(fentry_1) {
	//bpf_printk("fexit 1");
	return 0;
}

//SEC("fexit/xdp")
//int BPF_PROG(fexit_2) {
//	bpf_printk("fexit 2");
//	return 0;
//}
//
char _license[] SEC("license") = "GPL";

