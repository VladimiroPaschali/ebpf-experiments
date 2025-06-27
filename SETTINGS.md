> [!WARNING]
>  We tested `Inxpect` in a Intel Xeon processor. We don't know if it will work in other processors. 

# Set right PMC register

Processor manufacterer provides a set of registers to control the processor. These registers are called Performance Monitoring Counters (PMC). The number of register and the hex id of each register could change from processor to processor. 
In order to set the right PMC register, you need to know the hex id of the register you want to set and in `inpexct` set the right variable in the `[mykperf_module.c](/inxpect/kperf_/mykperf_module.c)` file. 

```c
#define CAP_EVENT 0x530000
#define FIRST_MSR_EV_SELECT_REG 0x186 // here we store the which event we want to monitor
#define MAX_MSR_PROG_REG 7
#define FIRST_MSR_PROG_REG 0xC1 // here we store the value of the event
```
- `CAP_EVENT` is the event capability, in Intel processors we use 0x53xxxx, where xxxx is the event number. My advice is to copy how `perf` does it.

- `FIRST_MSR_EV_SELECT_REG` is the first `event` selector programmable PMC register. In out CPU family, it is 0x186.

- `MAX_MSR_PROG_REG` is the number of programmable PMC registers. In our CPU family, it is 7.

- `FIRST_MSR_PROG_REG` is the first register where the `value` of the `event` associated with it is stored. In our CPU family, it is 0xC1. This mean that `how much times was counted the event` is stored in the register 0xC1 for the `event` in 0x186, and so on.

### How Inxpect use this variables

In order to try to adapt `Inxpect` to different processors, NEVER TESTED, the program use where the PMC register starts and how many registers are available. The program will try to set the `event` in the first register and if it fails, it will try to set the `event` in the next register until it finds a free register. Return the index (not the register number) of the register where the `event` was set. 

# Set right event

In `Inxpect` we hardcoded the event code composed by the `event` and the `umask`. On this blog [How to monitor the full range of CPU performance events](https://bnikolic.co.uk/blog/hpc-prof-events.html#:~:text=I%E2%80%99ll%20cover%20the%20second%20of%20these%20in%20later%20posts%2C%20but%20for%20time%20being%20here%20is%20how%20to%20figure%20out%20raw%20codes%20to%20use%3A) they talk about a tool that list all the events available in the processor and the hex code of each event. Another approach is to enable the event using `perf` and copy the hex code of the event from the `perf` output.

After you know the hex code of the event you want to monitor, you need to set the right variable in the `[inxpect.c](/inxpect/inxpect.c)` file. 
Here is an example of the `metrics` variable that we use in our project.
```c
struct event metrics[METRICS_NR] = {
    {.name = "instructions", .code = 0x00c0},          {.name = "cycles", .code = 0x003c},
    {.name = "cache-misses", .code = 0x412e},          {.name = "llc-misses", .code = 0x01b7},
    {.name = "L1-dcache-load-misses", .code = 0x0151},
};
```
The result stored in the `event` selector register will be using `instructions` = `0x5300c0`.
