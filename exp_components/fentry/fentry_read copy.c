#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <time.h>
#include <sys/syscall.h>

#include "fentry_read.skel.h"
#include "drop.skel.h"

int if_index = 0;
struct drop_bpf *skel_drop;
struct fentry_read_bpf *skel;

void exit_(int sig)
{
    fentry_read_bpf__detach(skel);

    int err;
    err = bpf_xdp_detach(if_index, 0, 0);
    if (err)
    {
        fprintf(stderr, "Failed to detach BPF program\n");
        exit(0);
    }

    drop_bpf__destroy(skel_drop);
    fentry_read_bpf__destroy(skel);
    exit(0);
}

int main(int argc, char *argv[])
{
    // LOAD DROP
    skel_drop = drop_bpf__open();
    if (!skel_drop)
    {
        perror("Unable to open skeleton\n");
        return -1;
    }

    if (drop_bpf__load(skel_drop) < 0)
    {
        perror("Unable to load skeleton\n");
        return -1;
    }

    signal(SIGINT, exit_);

    if_index = if_nametoindex(argv[1]);

    int err = bpf_xdp_attach(if_index, bpf_program__fd(skel_drop->progs.drop), 0, NULL);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    // LOAD ENTRY_READ
    int fd = bpf_program__fd(skel_drop->progs.drop);

    skel = fentry_read_bpf__open();

    struct bpf_program *program;
    bpf_object__for_each_program(program, skel->obj)
    {
        if (bpf_program__set_attach_target(program, fd, "drop") < 0)
        {
            perror("Unable to set attach tgt to dst prog\n");
            exit_(0);
            return -1;
        }
    }
    if (fentry_read_bpf__load(skel) < 0)
    {
        perror("Unable to load prog\n");
        exit_(0);
        return -1;
    }

    if (fentry_read_bpf__attach(skel) < 0)
    {
        perror("Unable to attach prog\n");
        exit_(0);
        return -1;
    }

    while (1)
        sleep(1);
}
