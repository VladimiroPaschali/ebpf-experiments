#ifndef __MYKEPERF_MODULE_H__
#define __MYKEPERF_MODULE_H__

#include <linux/if_link.h>
#include <linux/bpf.h>

#ifdef INTEL_CPU
#define get_counter(counter) 1 << 30 + counter
#else
#define get_counter(counter) counter
#endif

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)

#define RAND_FN bpf_get_prandom_u32()
#define MAX_ENTRIES_PERCPU_ARRAY 8

struct record_array
{
    __u64 value;
    __u64 run_cnt;
    char name[64];
    __u64 counter;
} __attribute__((aligned(64)));

struct histogram
{
    __u64 values[63];
} __attribute__((aligned(64)));

#define BPF_MYKPERF_INIT_TRACE()                                                                                       \
    __u64 bpf_mykperf__rdpmc(__u64 counter) __ksym;                                                                    \
    __u64 __sample_rate = 0;                                                                                           \
    __u64 run_cnt = 0;                                                                                                 \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                                       \
        __type(key, __u32);                                                                                            \
        __type(value, struct record_array);                                                                            \
        __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);                                                                 \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           \
    } percpu_output SEC(".maps");                                                                                      \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                                       \
        __type(key, __u32);                                                                                            \
        __type(value, struct histogram);                                                                               \
        __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);                                                                 \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           \
    } percpu_hist SEC(".maps");

#define DEFINE_SECTIONS(...) const char __sections[MAX_ENTRIES_PERCPU_ARRAY][15] = {__VA_ARGS__};

#define COUNT_RUN __sync_fetch_and_add(&run_cnt, 1);

// ------------------------- ARRAY MAP -------------------------------
#define BPF_MYKPERF_START_TRACE_ARRAY(sec_name)                                                                        \
    __u64 value_##sec_name = 0;                                                                                        \
    struct record_array *sec_name = {0};                                                                               \
    __u32 key_##sec_name = __COUNTER__;                                                                                \
    sec_name = bpf_map_lookup_elem(&percpu_output, &key_##sec_name);                                                   \
    struct histogram *sec_name##_histogram = bpf_map_lookup_elem(&percpu_hist, &key_##sec_name);                       \
                                                                                                                       \
    if (sec_name && sec_name->name[0] != 0)                                                                            \
    {                                                                                                                  \
        value_##sec_name = bpf_mykperf__rdpmc(sec_name->counter);                                                      \
    }

#define BPF_MYKPERF_START_TRACE_ARRAY_DEBUG(sec_name)                                                                  \
    __u64 value_##sec_name = 0;                                                                                        \
    struct record_array *sec_name = {0};                                                                               \
    int key_##sec_name = 0;                                                                                            \
    struct histogram *sec_name##_histogram = bpf_map_lookup_elem(&percpu_hist, &key_##sec_name);                       \
    value_##sec_name = bpf_mykperf__rdpmc(0);

#define BPF_MYKPERF_END_TRACE_ARRAY(sec_name)                                                                          \
    if (sec_name && sec_name->name[0] != 0)                                                                            \
    {                                                                                                                  \
        __u64 temp_value = bpf_mykperf__rdpmc(sec_name->counter);                                                      \
        if (LIKELY(temp_value >= value_##sec_name))                                                                    \
        {                                                                                                              \
            sec_name->value += (temp_value - value_##sec_name);                                                        \
            sec_name->run_cnt++;                                                                                       \
        }                                                                                                              \
        if (sec_name##_histogram)                                                                                      \
        {                                                                                                              \
            __u64 tmp = temp_value - value_##sec_name;                                                                 \
            if (tmp >= 63)                                                                                             \
                sec_name##_histogram->values[63]++;                                                                    \
            else                                                                                                       \
            {                                                                                                          \
                sec_name##_histogram->values[tmp]++;                                                                   \
            }                                                                                                          \
        }                                                                                                              \
    }

#define BPF_MYKPERF_END_TRACE_ARRAY_DEBUG(sec_name)                                                                    \
    __u64 temp_value = (bpf_mykperf__rdpmc(0) - value_##sec_name);                                                           \
    if (sec_name##_histogram != NULL)                                                                                  \
    {                                                                                                                  \
        if (temp_value >= 63)                                                                                          \
            sec_name##_histogram->values[63]++;                                                                        \
        else                                                                                                           \
            sec_name##_histogram->values[temp_value]++;                                                                \
    }

#define BPF_MYKPERF_START_TRACE_ARRAY_SAMPLED(sec_name)                                                                \
    __u64 value_##sec_name = 0;                                                                                        \
    struct record_array *sec_name = {0};                                                                               \
    __u32 key_##sec_name = __COUNTER__;                                                                                \
    struct histogram *sec_name##_histogram = bpf_map_lookup_elem(&percpu_hist, &key_##sec_name);                       \
    if (UNLIKELY(run_cnt % __sample_rate == 0))                                                                        \
    {                                                                                                                  \
        sec_name = bpf_map_lookup_elem(&percpu_output, &key_##sec_name);                                               \
        if (sec_name && sec_name->name[0] != 0)                                                                        \
        {                                                                                                              \
            value_##sec_name = bpf_mykperf__rdpmc(sec_name->counter);                                                  \
        }                                                                                                              \
    }

// --------------------- RING BUFFER --------------------------------
#define BPF_MYKPERF_START_TRACE(sec_name)                                                                              \
    struct record *sec_name = {0};                                                                                     \
    sec_name = bpf_ringbuf_reserve(&ring_output, sizeof(struct record), 0);                                            \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        memcpy(sec_name->name, #sec_name, sizeof(sec_name->name));                                                     \
        sec_name->type_counter = reg_counter;                                                                          \
        sec_name->value = bpf_mykperf__rdpmc(reg_counter);                                                             \
    }

#define BPF_MYKPERF_END_TRACE(sec_name)                                                                                \
    if (sec_name)                                                                                                      \
    {                                                                                                                  \
        sec_name->value = bpf_mykperf__rdpmc(reg_counter) - sec_name->value_##sec_name;                                \
        bpf_ringbuf_submit(sec_name, 0);                                                                               \
    }

#endif // __MYKEPERF_MODULE_H__
