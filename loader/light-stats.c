#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

// xdp prog management
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// if_nametoindex
#include <net/if.h>

// perf event
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

// profiler
#include "profiler/profiler.skel.h"
#include <mykperf_module.h>

// --- PRETTY PRINT -----
#define ERR "\033[1;31mERR\033[0m"
#define WARN "\033[1;33mWARN\033[0m"
#define INFO "\033[1;32mINFO\033[0m"
#define DEBUG "\033[1;34mDEBUG\033[0m"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_METRICS 8
#define MAX_MEASUREMENT 16
#define PINNED_PATH "/sys/fs/bpf/"

// metrics definition
struct profile_metric
{
    const char *name;

    struct perf_event_attr attr;
    bool selected;

    /* calculate ratios like instructions per cycle */
    const int ratio_metric; /* 0 for N/A, 1 for index 0 (cycles) */
    const char *ratio_desc;
    const float ratio_mul;
} metrics[] = {
    {
        // cycles
        .name = "cycles",
        .attr =
            {
                .type = PERF_TYPE_HARDWARE,
                .config = PERF_COUNT_HW_CPU_CYCLES,
                .exclude_user = 1,
            },
    },
    {
        // instructions
        .name = "instructions",
        .attr =
            {
                .type = PERF_TYPE_HARDWARE,
                .config = PERF_COUNT_HW_INSTRUCTIONS,
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "insns per cycle",
        .ratio_mul = 1.0,
    },
    {
        // branch misses
        .name = "branch-misses",
        .attr =
            {
                .type = PERF_TYPE_HARDWARE,
                .config = PERF_COUNT_HW_BRANCH_MISSES,
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "branch-misses per cycle",
        .ratio_mul = 1.0,
    },
    {
        // cache misses
        .name = "cache-misses",
        .attr =
            {
                .type = PERF_TYPE_HARDWARE,
                .config = PERF_COUNT_HW_CACHE_MISSES,
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "cache-misses per cycle",
        .ratio_mul = 1.0,
    },
    {
        // L1-dcache-load-misses
        .name = "L1-dcache-load-misses",
        .attr =
            {
                .type = PERF_TYPE_HW_CACHE,
                .config = (PERF_COUNT_HW_CACHE_L1D | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                           (PERF_COUNT_HW_CACHE_RESULT_MISS << 16)),
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "L1-dcache-load-misses per cycle",
        .ratio_mul = 1.0,
    },
    {
        // LLC-load-misses
        .name = "LLC-load-misses",
        .attr =
            {
                .type = PERF_TYPE_HW_CACHE,
                .config = (PERF_COUNT_HW_CACHE_LL | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                           (PERF_COUNT_HW_CACHE_RESULT_MISS << 16)),
                .exclude_user = 1,
            },
        .ratio_metric = 1,
        .ratio_desc = "LLC-load-misses per cycle",
        .ratio_mul = 1.0,
    },
};

#define MAX_PROG_FULL_NAME 15
#define NS_PER_SECOND 1000000000

int verbose;
int perf_fd;
struct bpf_prog_info info;
__u32 info_len;
int prog_fd;
int prog_id;
char func_name[15];
char filename[256];
char *prog_name;
int n_cpus;
int *perf_event_fds;
struct record_array *data;
int array_map_fd;
__u32 timeout;

struct profile_metric selected_metrics[MAX_METRICS];
int selected_metrics_cnt;

// TODO - acc fn
int accumulate;

void usage()
{
    printf("Usage: light-stats [options]\n");
    printf("Options:\n");
    printf("  -e <metric1,metric2,...>  Select metrics\n");
    printf("  -n <prog_name>            Program name\n");
    printf("  -m <mode>                 XDP mode\n");
    printf("  -a                        Accumulate stats\n");
    printf("  -c                        Enable run count\n");
    printf("  -v                        Verbose\n");
    printf("  -s                        Supported metrics\n");
    printf("  -h                        Help\n");
}

void supported_metrics()
{
    printf("Supported metrics:\n");
    for (int i = 0; i < ARRAY_SIZE(metrics); i++)
    {
        printf("  %s\n", metrics[i].name);
    }
}

// from bpftool
static int prog_fd_by_nametag(char nametag[15])
{
    unsigned int id = 0;
    int err;
    int fd = -1;

    while (true)
    {
        struct bpf_prog_info info = {};
        __u32 len = sizeof(info);

        err = bpf_prog_get_next_id(id, &id);
        if (err)
        {
            if (errno != ENOENT)
            {
                fprintf(stderr, "[%s]: can't get next prog id: %s", ERR, strerror(errno));
            }
            return -1;
        }

        fd = bpf_prog_get_fd_by_id(id);
        if (fd < 0)
        {
            fprintf(stderr, "[%s]: can't get prog fd (%u): %s", ERR, id, strerror(errno));
            return -1;
        }

        err = bpf_prog_get_info_by_fd(fd, &info, &len);
        if (err)
        {
            fprintf(stderr, "[%s]: can't get prog info by fd (%u): %s", ERR, id, strerror(errno));
            return -1;
        }

        if (strncmp(nametag, info.name, sizeof(info.name)) == 0)
        {
            break;
        }
    }

    return fd;
}

static int handle_event(struct record_array *data)
{
    struct record_array sample = {0};

    // accumulate for each cpu
    for (int cpu = 0; cpu < n_cpus; cpu++)
    {
        if (data[cpu].name[0] != 0)
        {
            sample.value += data[cpu].value;
            sample.run_cnt += data[cpu].run_cnt;
            if (sample.name[0] == 0)
            {
                strcpy(sample.name, data[cpu].name);
                sample.type_counter = data[cpu].type_counter;
            }
        }
    }

    if (sample.name[0] == 0)
    {
        return 0;
    }

    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // FORMAT OUTPUT
    char *fmt = "%s     %s: %llu  %.2f/pkt - %u run_cnt\n";

    fprintf(stdout, fmt, ts, sample.name, sample.value, (float)sample.value / sample.run_cnt, sample.run_cnt);
    fflush(stdout);

    return 0;
}

void print_accumulated_stats()
{
    struct record_array sample = {0};
    int err;
    // read percpu array
    for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
    {
        sample.name[0] = 0;
        err = bpf_map_lookup_elem(array_map_fd, &key, data);
        if (err)
        {
            continue;
        }
        // accumulate for each cpu
        for (int cpu = 0; cpu < n_cpus; cpu++)
        {
            if (data[cpu].name[0] != 0)
            {
                sample.value += data[cpu].value;
                sample.run_cnt += data[cpu].run_cnt;
                if (sample.name[0] == 0)
                {
                    strcpy(sample.name, data[cpu].name);
                    sample.type_counter = data[cpu].type_counter;
                }
            }
        }

        if (sample.name[0] != 0)
        {
            fprintf(stdout, "    %s: %'llu  - %'u run_count\n\n", sample.name, sample.value, sample.run_cnt);
        }
    }
    return;
}

static void init_exit(int sig)
{

    for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
    {
        if (bpf_map_lookup_elem(array_map_fd, &key, data))
            continue;

        handle_event(data);
    }

    free(data);

    // set locale to print numbers with dot as thousands separator
    setlocale(LC_NUMERIC, "");

    // print accumulated stats
    print_accumulated_stats();

    fprintf(stdout, "[%s]: Done \n", INFO);
    exit(0);
}

static void poll_stats(unsigned int map_fd)
{
    int err;

    while (1)
    {
        // read percpu array
        for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
        {
            err = bpf_map_lookup_elem(map_fd, &key, data);
            if (err)
            {
                continue;
            }
            handle_event(data);
        }
        sleep(timeout);
    }
}

int main(int arg, char **argv)
{
    int err, opt;

    // set shared var
    n_cpus = libbpf_num_possible_cpus();
    selected_metrics_cnt = 0;
    prog_name = NULL;
    info_len = sizeof(info);
    data = malloc(n_cpus * sizeof(struct record_array));
    array_map_fd = -1;
    timeout = 3;

    // retrieve opt
    while ((opt = getopt(arg, argv, "e:n:o:P:t:acvsh")) != -1)
    {
        switch (opt)
        {
        case 'e':
            // parse metrics
            char *token = strtok(optarg, ",");
            while (token != NULL)
            {
                for (int i = 0; i < ARRAY_SIZE(metrics); i++)
                {
                    if (strcmp(token, metrics[i].name) == 0)
                    {
                        metrics[i].selected = true;
                        memcpy(&selected_metrics[selected_metrics_cnt], &metrics[i], sizeof(struct profile_metric));
                        selected_metrics_cnt++;
                    }
                }
                token = strtok(NULL, ",");
            }
            break;
        case 'P':
            prog_name = optarg;
            break;
        case 'n':
            strcpy(func_name, optarg);
            break;
        case 't':
            timeout = atoi(optarg);
            break;
        case 'a':
            accumulate = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage();
            return 0;
        case 's':
            supported_metrics();
            return 0;
        default:
            fprintf(stderr, "Invalid option: %c\n", opt);
            usage();
            return 1;
        }
    }

    // set trap for ctrl+c
    signal(SIGINT, init_exit);
    signal(SIGTERM, init_exit);

    char filename_map[256];
    err = snprintf(filename_map, sizeof(filename_map), "%s%s", PINNED_PATH, "percpu_output");
    if (err < 0)
    {
        fprintf(stderr, "[%s]: creating filename for pinned path: %s\n", ERR, strerror(errno));
        return 1;
    }

    // retrieve map fd from pinned path
    array_map_fd = bpf_obj_get(filename_map);
    if (array_map_fd < 0)
    {
        fprintf(stderr, "[%s]: getting map fd from pinned path: %s\nbe sure %s program own 'percpu_output' map", ERR,
                filename_map, func_name);
        return 1;
    }

    /*
     * we must delete the events received before this tool was started,
     * otherwise some statistics would have wrong values compared with the data calculated by the tool.
     * The statistics involved:
     *   - percentage of samples
     */

    // update each element of the map with a zeroed array
    unsigned char *reset = calloc(n_cpus, sizeof(struct record_array));

    for (__u32 key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
    {
        err = bpf_map_update_elem(array_map_fd, &key, reset, 0);
        if (err)
        {
            fprintf(stderr, "[%s]: deleting map element: %s\n", ERR, strerror(errno));
            return 1;
        }
    }

    free(reset);

    // retrieve prog fd
    prog_fd = prog_fd_by_nametag(func_name);
    if (prog_fd < 0)
    {
        fprintf(stderr, "[%s]: during prog fd retreive for program name: %s\n", ERR, func_name);
        return 1;
    }

    // get prog name
    // check if id is the same specified by -n
    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (err)
    {
        fprintf(stderr, "[%s]: during getting prog info by fd: %d\n", ERR, prog_fd);
        return 1;
    }

    // set prog name
    if (!prog_name)
    {
        prog_name = info.name;
    }

    fprintf(stdout, "[%s]: Program name: %s\n", DEBUG, info.name);

    fprintf(stdout, "[%s]: Running... \nPress Ctrl+C to stop\n", INFO);
    if (array_map_fd > 0)
    {
        // start perf before polling
        poll_stats(array_map_fd);
    }
    else
    {
        printf("[%s]: Stats not enabled\n", INFO);
        pause();
    }

    // there is a remote possibility that the poll_stats function will return an error
    // and the programm will end without calling init_exit function
    // so we call it here
    init_exit(0);

    return 0;
}
