
#include <asm/types.h>
#define CACHE_MISSES  1
#define EVENT  CACHE_MISSES
#define MAGIC 'e'

#define ENABLE_EVENT _IOWR(MAGIC, 1, uint64_t)
#define DISABLE_EVENT _IOW(MAGIC, 2, uint64_t)
#define SET_CPU _IOW(MAGIC, 3, int)

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define LIKELY(x) __builtin_expect(!!(x), 1)

#define RAND_FN bpf_get_prandom_u32()
#define MAX_ENTRIES_PERCPU_ARRAY 16

#define get_counter(counter) (0<<30) + counter 

struct record_array
{
    __u64 value;
    __u32 run_cnt;
    char name[15];
    __u8 type_counter;
} __attribute__((aligned(32)));

#define BPF_MYKPERF_INIT_TRACE()                                                                                       \
    __u64 bpf_mykperf_rdmsr(__u64 counter) __ksym;                                                                 \
                                                                                                                       \
    struct                                                                                                             \
    {                                                                                                                  \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                                       \
        __type(key, __u32);                                                                                            \
        __type(value, struct record_array);                                                                            \
        __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);                                                                 \
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           \
    } percpu_output SEC(".maps");


#define BPF_MYKPERF_START_TRACE_ARRAY(sec_name, counter) \
	__u64 value_##sec_name = bpf_mykperf_rdmsr(counter);\

#define BPF_MYKPERF_END_TRACE_ARRAY(sec_name, counter, id)                                                             \
    if (value_##sec_name)                                                                                              \
    {                                                                                                                  \
        value_##sec_name =  bpf_mykperf_rdmsr(counter)  - value_##sec_name;                                         \
        __u32 key = id;                                                                                                \
        struct record_array *sec_name = {0};                                                                           \
        sec_name = bpf_map_lookup_elem(&percpu_output, &key);                                                          \
        if (LIKELY(sec_name))                                                                                          \
        {                                                                                                              \
            sec_name->value += value_##sec_name;                                                                       \
            sec_name->run_cnt++;                                                                                       \
            if (sec_name->name[0] == 0)                                                                                \
            {                                                                                                          \
                memcpy(sec_name->name, #sec_name, sizeof(sec_name->name));                                             \
                sec_name->type_counter = counter;                                                                      \
            }                                                                                                          \
        }                                                                                                              \
    }

#define BPF_MYKPERF_START_TRACE_ARRAY_SAMPLED(sec_name, counter, sample_rate)                                          \
    if (UNLIKELY(RAND_FN & sample_rate))                                                                               \
    {                                                                                                                  \
        BPF_MYKPERF_START_TRACE_ARRAY(sec_name, counter)                                                               \
    }

