#include <stdio.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "tail.skel.h"

struct tail_bpf *skel;

void exit(int sig)
{
    tail_bpf__destroy(skel);
    exit(0);
}

int main(int argc, char **argv)
{
    int err;

    skel = tail_bpf__open();

    err = tail_bpf__load(skel);
    if (err)
    {
        printf("erropr load");
        return -1;
    }

    __u32 key = 0;
    __u32 value = bpf_program__fd(skel->progs.xdp_2);
    err = bpf_map__update_elem(skel->maps.bpf_prog_info, &key, sizeof(key), &value, sizeof(int), 0);

    if (err)
    {
        printf("erropr update:");
        return -1;
    }

    signal(SIGINT, exit);

    while (1)
    {
    }

    tail_bpf__destroy(skel);

    return 0;
}