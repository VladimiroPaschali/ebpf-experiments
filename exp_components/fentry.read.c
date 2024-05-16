#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>

#include "fentry.read.skel.h"

int main(int argc, char *argv[])
{
    int fd = atoi(argv[1]);
    int cpu = atoi(argv[3]);

    struct fentry_read_bpf *skel = fentry_read_bpf__open();
    int dst_prog = bpf_prog_get_fd_by_id(fd);
    if (dst_prog < 0)
    {
        perror("Unable to open dst prog\n");
        return -1;
    }
    struct bpf_program *program;
    bpf_object__for_each_program(program, skel->obj)
    {
        if (bpf_program__set_attach_target(program, dst_prog, argv[2]) < 0)
        {
            perror("Unable to set attach tgt to dst prog\n");
            return -1;
        }
    }
    if (fentry_read_bpf__load(skel) < 0)
    {
        perror("Unable to load prog\n");
        return -1;
    }

    // get map fd
    int map_fd = bpf_map__fd(skel->maps.perf_map);

    // set map
    int pmu_fd;

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
        return -1;
    }

    __u32 zero = 0;
    if (bpf_map_update_elem(map_fd, &zero, &pmu_fd, BPF_ANY) || ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0))
    {
        close(pmu_fd);
        return -1;
    }

    if (fentry_read_bpf__attach(skel) < 0)
    {
        perror("Unable to attach prog\n");
        return -1;
    }

    while (1)
        ;
}
