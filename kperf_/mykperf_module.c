#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include "mykperf_module.h"

//static __u64 mykperf_read_rdpmc(__u8 counter__k, __u32 low, __u32 high);

// -------------------- bpf prototypes ------------------------
__bpf_kfunc __u64 bpf_mykperf_read_rdpmc(__u8 counter__k);

/* #define mykperf_rdpmc(counter, low, high)                                                                              \
    __asm__ __volatile__("rdpmc" : "=a"(low), "=d"(high) : "c"(counter));                                              \
    __asm__ __volatile__("lfence" : :); */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A Dummy Kernel Module");

/* static __u64 mykperf_read_rdpmc(__u8 counter__k, __u32 low, __u32 high)
{
    mykperf_rdpmc(counter__k, low, high);
    return ((__u64)high << 32) | low;
} */

__bpf_kfunc __u64 bpf_mykperf_read_rdpmc(__u8 counter__k)
{
    __u64 ret = 0;
    rdpmcl(counter__k, ret);
    return ret;
}

BTF_SET8_START(bpf_task_set)
BTF_ID_FLAGS(func, bpf_mykperf_read_rdpmc)
BTF_SET8_END(bpf_task_set)

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_task_set,
};

static int __init mykperf_module_init(void)
{
    register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set);
    // register_btf_kfunc_id_set(BPF_PROG_TYPE_PERF_EVENT, &bpf_task_kfunc_set);
    // register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACEPOINT, &bpf_task_kfunc_set);
    // register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_task_kfunc_set);
    // register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT, &bpf_task_kfunc_set);
    register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_task_kfunc_set);

    pr_info("kfunc registerd with success\n");
    return 0;
}

static void __exit mykperf_module_exit(void)
{
    pr_info("kernel module detached\n");
}

module_init(mykperf_module_init);
module_exit(mykperf_module_exit);
