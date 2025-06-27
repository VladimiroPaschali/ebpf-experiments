#ifndef __MYKEPERF_MODULE_H__
#define __MYKEPERF_MODULE_H__

#include <linux/bpf.h>
#include <linux/if_link.h>

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

#define MAX_REGISTER 4

struct record_array {
  __u64 value;
  __u64 run_cnt;
  char name[15];
  __u64 counter;
} __attribute__((aligned(64)));

struct record {
  char name[16];
  __u64 run_cnts[4];
  __u64 values[4];
  __u32 counters[4];
} __attribute__((aligned(64)));

#define BPF_MYKPERF_INIT_TRACE()                                               \
  __u64 bpf_mykperf__rdpmc(__u64 counter) __ksym;                              \
  void bpf_mykperf__fence(void) __ksym;                                        \
  __u64 sample_rate = 0;                                                     \
  __u64 run_cnt = 0;                                                           \
  __u32 multiplex_rate = 8;                                                    \
  __u8 num_counters = 4;                                                       \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                   \
    __type(key, __u32);                                                        \
    __type(value, struct record);                                              \
    __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);                             \
    __uint(pinning, LIBBPF_PIN_BY_NAME);                                       \
  } multiplexed_output SEC(".maps");                                           \
  struct{                                                                     \
      __uint(type, BPF_MAP_TYPE_ARRAY);                                       \
    __type(key, __u32);                                                        \
    __type(value, struct record_array);                                        \
    __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);                             \
    __uint(pinning, LIBBPF_PIN_BY_NAME);                                       \
    } percpu_output SEC(".maps"); \

#define DEFINE_SECTIONS(...)                                                   \
  const char __sections[MAX_ENTRIES_PERCPU_ARRAY][16] = {__VA_ARGS__};

#define COUNT_RUN run_cnt++;

// ------------------------ MULTIPLEXED COUNTERS -------------------------
#define BPF_MYKPERF_START_TRACE_MULTIPLEXED(sec_name)                           \
  COUNT_RUN;                                                                   \
  bpf_mykperf__fence();                                                        \
  __u64 value_##sec_name = 0;                                                  \
  struct record *sec_name = {0};                                               \
  __u32 key_##sec_name = __COUNTER__;                                          \
  __u64 index_##sec_name =                                                     \
      ((run_cnt / multiplex_rate) % num_counters) % MAX_REGISTER;              \
  sec_name = bpf_map_lookup_elem(&multiplexed_output, &key_##sec_name);        \
  if (LIKELY(sec_name) && sec_name->name[0] != '\0') {                         \
    value_##sec_name =                                                         \
        bpf_mykperf__rdpmc(sec_name->counters[index_##sec_name]);              \
  } \

#define BPF_MYKPERF_START_TRACE_MULTIPLEXED_SAMPLED(sec_name)                           \
  COUNT_RUN;                                                                   \
  bpf_mykperf__fence();                                                        \
  __u64 value_##sec_name = 0;                                                  \
  struct record *sec_name = {0};                                               \
  __u32 key_##sec_name = __COUNTER__; \              
  __u64 index_##sec_name =                                                     \
      ((run_cnt / multiplex_rate) % num_counters) % MAX_REGISTER;              \
  if (UNLIKELY(run_cnt % (1 << sample_rate) == 0)) {                            \
    sec_name = bpf_map_lookup_elem(&multiplexed_output, &key_##sec_name);        \
    if (LIKELY(sec_name) && sec_name->name[0] != '\0') {                         \
      value_##sec_name =                                                         \
          bpf_mykperf__rdpmc(sec_name->counters[index_##sec_name]);              \
     }                                                                           \
  }

#define BPF_MYKPERF_END_TRACE_MULTIPLEXED(sec_name)                             \
  {                                                                            \
    if (LIKELY(sec_name) && sec_name->name[0] != '\0') {                       \
      __u64 temp_value =                                                       \
          bpf_mykperf__rdpmc(sec_name->counters[index_##sec_name]);            \
      if (temp_value >= value_##sec_name) {                                    \
        sec_name->values[index_##sec_name] += (temp_value - value_##sec_name); \
        sec_name->run_cnts[index_##sec_name]++;                                \
      }                                                                        \
    }                                                                          \
  }

// ------------------------- ARRAY MAP -------------------------------
#define BPF_MYKPERF_START_TRACE_ARRAY(sec_name)                                \
COUNT_RUN;                                                                   \  
bpf_mykperf__fence();                                                        \
  __u64 value_##sec_name = 0;                                                  \
  struct record_array *sec_name = {0};                                         \
  __u32 key_##sec_name = __COUNTER__;                                          \
  sec_name = bpf_map_lookup_elem(&percpu_output, &key_##sec_name);             \
  if (LIKELY(sec_name && sec_name->name[0] != '\0')) {                         \
    value_##sec_name = bpf_mykperf__rdpmc(sec_name->counter);                  \
  }

#define BPF_MYKPERF_START_TRACE_ARRAY_SAMPLED(sec_name)                        \
  __u64 value_##sec_name = 0;                                                  \
  struct record_array *sec_name = {0};                                         \
  __u32 key_##sec_name = __COUNTER__;                                          \
  if (UNLIKELY(run_cnt % (1 << sample_rate) == 0)) {                           \
    sec_name = bpf_map_lookup_elem(&percpu_output, &key_##sec_name);           \
    if (sec_name && sec_name->name[0] != '\0') {                               \
      value_##sec_name = bpf_mykperf__rdpmc(sec_name->counter);                \
    }                                                                          \
  }

#define BPF_MYKPERF_END_TRACE_ARRAY(sec_name)                                  \
  {                                                                            \
    if (LIKELY(sec_name && sec_name->name[0] != '\0')) {                       \
      __u64 temp_value = bpf_mykperf__rdpmc(sec_name->counter);                \
      if (temp_value >= value_##sec_name) {                                    \
        sec_name->value += (temp_value - value_##sec_name);                    \
        sec_name->run_cnt++;                                                   \
      }                                                                        \
    }                                                                          \
  }

#define BPF_MYKPERF_END_TRACE_ARRAY_SAMPLED(sec_name)                          \
  {                                                                            \
    if (UNLIKELY(sec_name && sec_name->name[0] != '\0')) {                     \
      __u64 temp_value = bpf_mykperf__rdpmc(sec_name->counter);                \
      if (temp_value >= value_##sec_name) {                                    \
        sec_name->value += (temp_value - value_##sec_name);                    \
        sec_name->run_cnt++;                                                   \
      }                                                                        \
    }                                                                          \
  }

// --------------------- RING BUFFER --------------------------------
#define BPF_MYKPERF_START_TRACE(sec_name)                                      \
  struct record *sec_name = {0};                                               \
  sec_name = bpf_ringbuf_reserve(&ring_output, sizeof(struct record), 0);      \
  if (sec_name) {                                                              \
    memcpy(sec_name->name, #sec_name, sizeof(sec_name->name));                 \
    sec_name->type_counter = reg_counter;                                      \
    sec_name->value = bpf_mykperf__rdpmc(reg_counter);                         \
  }

#define BPF_MYKPERF_END_TRACE(sec_name)                                        \
  if (sec_name) {                                                              \
    sec_name->value =                                                          \
        bpf_mykperf__rdpmc(reg_counter) - sec_name->value_##sec_name;          \
    bpf_ringbuf_submit(sec_name, 0);                                           \
  }

#endif // __MYKEPERF_MODULE_H__
