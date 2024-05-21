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

    // get map fd
    int map_fd = bpf_map__fd(skel->maps.perf_map);

    // set map
    int pmu_fd;
    int cpu = atoi(argv[2]);

    struct perf_event_attr attr = {
        .type = PERF_TYPE_HARDWARE,
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .exclude_user = 1,
    };

    pmu_fd = syscall(__NR_perf_event_open, &attr, -1 /*pid*/, cpu, -1 /*group_fd*/, 0);
    if (pmu_fd < 0)
    {
        if (errno == ENODEV)
        {
            return 0;
        }
        exit_(0);
        return -1;
    }

    __u32 zero = 0;
    if (bpf_map_update_elem(map_fd, &zero, &pmu_fd, BPF_ANY) || ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0))
    {
        close(pmu_fd);
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
