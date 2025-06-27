#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "nat_structs.h"
#include "xdp_nat.skel.h"

#define PRIV_SUBNET 0xc0a80102;
#define PUB_SUBNET 0x0a000002;
#define TCP_PROTO 6
#define UDP_PROTO 17

struct xdp_nat_bpf *skel;
int ifindex = -1;

static void exit_(int sig)
{
    int err;

    err = bpf_xdp_detach(ifindex, 0, 0);
    if (err)
    {
        fprintf(stderr, "ERR: detach from %d\n", ifindex);
        exit(1);
    }
    if (skel)
        xdp_nat_bpf__destroy(skel);
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex)
    {
        fprintf(stderr, "ERR: if_nametoindex(%s) failed\n", argv[1]);
        return 1;
    }

    skel = xdp_nat_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "ERR: xdp_nat_bpf__open failed\n");
        return 1;
    }

    int err = xdp_nat_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "ERR: xdp_nat_bpf__load failed\n");
        return 1;
    }

    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_nat), 0, 0);
    if (err)
    {
        fprintf(stderr, "ERR: bpf_xdp_attach failed\n");
        return 1;
    }

    signal(SIGINT, exit_);
    signal(SIGTERM, exit_);

    printf("Started\n");
    fflush(stdout);

    for (;;)
        sleep(1);
    return 0;
}