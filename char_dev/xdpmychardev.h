#ifndef _XDPMYCHARDEV_H_
#define _XDPMYCHARDEV_H_

#include <asm/types.h>
#include <stdlib.h>

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)

#define RAND_FN bpf_get_prandom_u32()
#define MAX_ENTRIES_PERCPU_ARRAY 16

struct record_array
{
    __u64 value;
    __u64 run_cnt;
    char name[15];
    __u64 type_counter;
} __attribute__((aligned(32)));

#define BPF_MYKPERF_INIT_TRACE()                                                                                       \
    __u64 bpf_mykperf_rdmsr(__u64 counter) __ksym;                                                                     \
    __u64 reg_counter = 0;                                                                                             \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                                       \
        __type(key, __u32);                                                                                            \
        __type(value, struct record_array);                                                                            \
        __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);                                                                 \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           \
    } percpu_output SEC(".maps");

#define BPF_MYKPERF_START_TRACE_ARRAY(sec_name)                                                                        \
    __u64 value_##sec_name = 0;                                                                                        \
    if (reg_counter)                                                                                                   \
    {                                                                                                                  \
        value_##sec_name = bpf_mykperf_rdmsr(reg_counter);                                                             \
    }
#define BPF_MYKPERF_END_TRACE_ARRAY(sec_name, index)                                                                   \
    if (value_##sec_name)                                                                                              \
    {                                                                                                                  \
        value_##sec_name = (__u64)abs(bpf_mykperf_rdmsr(reg_counter) - value_##sec_name);                              \
        __u32 key = index;                                                                                             \
        struct record_array *sec_name = {0};                                                                           \
        sec_name = bpf_map_lookup_elem(&percpu_output, &key);                                                          \
        if (LIKELY(sec_name))                                                                                          \
        {                                                                                                              \
            sec_name->value += value_##sec_name;                                                                       \
            sec_name->run_cnt++;                                                                                       \
            if (sec_name->name[0] == 0)                                                                                \
            {                                                                                                          \
                memcpy(sec_name->name, #sec_name, sizeof(sec_name->name));                                             \
                sec_name->type_counter = reg_counter;                                                                  \
            }                                                                                                          \
        }                                                                                                              \
    }

#define BPF_MYKPERF_START_TRACE_ARRAY_SAMPLED(sec_name, sample_rate)                                                   \
    if (UNLIKELY(RAND_FN & sample_rate))                                                                               \
    {                                                                                                                  \
        BPF_MYKPERF_START_TRACE_ARRAY(sec_name, reg_counter)                                                           \
    }

#define BPF_MYKPERF_START_TRACE(sec_name)                                                                              \
    struct record *sec_name = {0};                                                                                     \
    sec_name = bpf_ringbuf_reserve(&ring_output, sizeof(struct record), 0);                                            \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        memcpy(sec_name->name, #sec_name, sizeof(sec_name->name));                                                     \
        sec_name->type_counter = reg_counter;                                                                          \
        sec_name->value = bpf_mykperf_rdmsr(reg_counter);                                                              \
    }

#define BPF_MYKPERF_END_TRACE(sec_name)                                                                                \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        sec_name->value = bpf_mykperf_rdmsr(reg_counter) - sec_name->value;                                            \
        bpf_ringbuf_submit(sec_name, 0);                                                                               \
    }

#endif // _XDPMYCHARDEV_H_