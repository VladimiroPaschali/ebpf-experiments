# loader-stats

This is a simple tool to load XDP programs and collect statistics about them.

The statistics are collected using `BPF_MYKPERF` macros that must be used in the XDP program. More about `BPF_MYKPERF` can be found [here](#how-bpf_mykperf-works) or later in this document.

## Usage

There are two ways to use this tool: loading a program and collecting statistics, or just collecting statistics.

### Loading a program and collecting statistics

To load a program and collect statistics, you must specify the path to the program and the events you want to collect statistics about.

```bash
loader-stats -i <interface> -f <xdp_filename> -e <event1,event2...> 
```
See the [options](#options) for more information.

### Collecting statistics

It's possible to collect statistics from a program that is already loaded. You must specify the prog name and events you want to collect statistics about.

```bash
loader-stats -i <interface> -n <prog_name> -e <event1,event2...> [-v | -a | -o <output_filename> | -x | -s | -h]
```
See the [options](#options) for more information.

### Options

- `-i <interface>`: specify the interface to attach the program.
- `-f <xdp_filename>`: specify the path to the XDP program.
- `-n <prog_name>`: specify the name of the program to collect statistics, it must be loaded yet.
- `-e <event1,event2...>`: specify the events to collect statistics about, the tool will enable the perf events. The events must be separated by commas.
  Without `-e` the tool will not print any statistics, but on kernel side they will be stored in the map.
- `-m <mode>`: specify the mode to attach the program. The options are `skb`, `native`. If not specified or passed an invalid argument, the default is `native`.
- `-o <output_filename>`: specify the output filename to store the statistics.
- `-v`: verbose mode, print warnings and minor information.
- `-a`: don't print during the execution, just print the statistics at the end.
- `-c`: attach a fexit program to the XDP program to count the number of times the program was executed.
- `-s`: print the supported events.
- `-x`: enable a plot of the statistics. This option requires the `gnuplot` package.
- `-h`: print the help message.



## How BPF_MYKPERF works

### BPF_MYKPERF_INIT()  
This macro initializes the statistics. It creates a map to store the statistics and defines the kfunc prototype.
The map are defined as:
```c
    struct                                                                                                             
    {                                                                                                                  
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                                                                       
        __type(key, __u32);                                                                                            
        __type(value, struct record_array);                                                                            
        __uint(max_entries, MAX_ENTRIES_PERCPU_ARRAY);                                                                
        __uint(pinning, LIBBPF_PIN_BY_NAME);                                                                           
    } percpu_output SEC(".maps");
```

The map store `struct record_array` that is defined as:
```c
struct record_array
{
    __u64 value;        // where the statistics are summed
    __u32 run_cnt;      // how many times the section was executed
    char name[15];      // the name of the section
    __u8 type_counter;  // the counter associated to the perf event
} __attribute__((aligned(32)));
```

### BPF_MYKPERF_START_TRACE_ARRAY(sec_name, counter)
This macro starts the profiling of a section. 
Every time this macro is called, a new measurement is started.
It call the function `bpf_mykperf_read_rdpmc` with the `counter` specified in the argument and store the result in `value__sec_name` variable.

### BPF_MYKPERF_END_TRACE_ARRAY(sec_name, counter, index)
This macro ends the profiling of a section.
It call the function `bpf_mykperf_read_rdpmc` with the `counter` specified in the argument and store the difference between the result and the previous value in `value__sec_name` variable.
Then, it stores name, value, counter and run_cnt in the map.


## How to use BPF_MYKPERF

The first step is to call `BPF_MYKPERF_INIT` to initialize the statistics.
This macro will create a map to store the statistics, and define the kfunc prototype.
Don't accept any arguments.

_E.g._:
```c
BPF_MYKPERF_INIT();

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
        ...
}
```
To start profiling, call `BPF_MYKPERF_START_TRACE_ARRAY(name, counter)` at the beginning of the code block you want to profile.
- name: the name of the section, it's just to identify the section in user space.
- counter: the counter associated to the perf event enabled by the tool. These counter follow the same order as the specified event in the tool. 
For example if the specified events are `-e instructions,cycles`, the counter for instructions is 0 and for cycles is 1 and so on.

To end profiling, call `BPF_MYKPERF_END_TRACE_ARRAY(name, counter, index)` at the end of the code block you want to profile.
Obviously, the name and counter must match the `BPF_MYKPERF_START_TRACE_ARRAY` call. 
- index: the index of the percpu array where the statistics are stored. This is used to store the statistics in the correct place, eache section must have a unique index. Otherwise, the statistics will be wrong.

_E.g._:
```c
BPF_MYKPERF_START("xdp", 0);
```
