#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include "kfunc.skel.h"

int if_index;
struct kfunc_bpf *skel;

void exit_(int sig)
{
    int err = bpf_xdp_detach(if_index, 0, 0);
    if (err)
    {
        fprintf(stderr, "Failed to detach BPF program\n");
        return;
    }

    kfunc_bpf__destroy(skel);
    exit(0);
}

int main(int argc, char **argv)
{

    skel = kfunc_bpf__open();
    if (!skel)
    {
        perror("Unable to open skeleton\n");
        return -1;
    }

    if (kfunc_bpf__load(skel) < 0)
    {
        perror("Unable to load skeleton\n");
        return -1;
    }

    if_index = if_nametoindex(argv[1]);

    int err = bpf_xdp_attach(if_index, bpf_program__fd(skel->progs.kfunc), 0, NULL);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    signal(SIGTERM, exit_);
    signal(SIGINT, exit_);

    while (1)
    {
        sleep(1);
    }

    exit_(0);

    return 0;
}