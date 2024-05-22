#ifndef __USER_MYCHARDEV_H__
#define __USER_MYCHARDEV_H__

#include <asm/types.h>

#define PINNED_PROG_PATH "/sys/fs/bpf/"
#define BSS_MAP ".bss"
#define RODATA_MAP ".rodata"

#define MAX_PROG_FULL_NAME 16
#define MAX_PSECTIONS 8

struct message
{
    __u64 event;
    __u64 reg;
    int cpu;
};

struct bss
{
    __u32 __sample_rate;
    __u64 run_cnt;
};

struct rodata
{
    char sections[MAX_PSECTIONS][MAX_PROG_FULL_NAME];
};

int get_bss_map_fd();
int get_rodata_map_fd();
int enable_event(__u64 event, int *out_reg, int cpu);
int disable_event(__u64 event, __u64 reg, int cpu);

#endif // __USER_MYCHARDEV_H_