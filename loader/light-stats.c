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

// profiler
static struct profiler *profile_obj;
int enable_run_cnt;
__u64 run_cnt;

// output file
FILE *output_file;
char output_filename[256];

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
    printf("  -o <filename>             Output file\n");
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

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int start_perf(int n_cpus)
{
    for (int i = 0; i < selected_metrics_cnt; i++)
    {
        for (int cpu = 0; cpu < n_cpus; cpu++)
        {
            perf_fd = perf_event_open(&selected_metrics[i].attr, -1, cpu, -1, 0);
            if (perf_fd < 0)
            {
                if (errno == ENODEV)
                {
                    if (verbose)
                    {
                        fprintf(stderr, "[%s]: cpu: %d may be offline\n", WARN, cpu);
                    }
                    continue;
                }
                else
                {
                    fprintf(stderr, "[%s]: perf_event_open failed - cpu: %d metric: %s\n", ERR, cpu,
                            selected_metrics[i].name);
                }
            }

            // enable perf event
            if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0))
            {
                fprintf(stderr, "[%s]: ioctl failed - cpu: %d metric: %s\n", ERR, cpu, selected_metrics[i].name);
                return -1;
            }
            perf_event_fds[cpu + i] = perf_fd;
        }
    }
    return 0;
}

static void print_accumulated_stats()
{
    struct record_array sample = {0};
    int err;
    // read percpu array
    for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
    {
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
            fprintf(stdout, "    %s: %'llu  - %'u run_counts \n\n", sample.name, sample.value, sample.run_cnt);
        }
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
    char *fmt = "%s     %s: %llu    (%s)  %.2f/pkt - %u run_cnt\n";

    if (output_file != NULL)
    {
        fprintf(output_file, fmt, ts, selected_metrics[sample.type_counter].name, sample.value, sample.name,
                (float)sample.value / sample.run_cnt, sample.run_cnt);
    }

    if (!output_file)
    {

        fprintf(stdout, fmt, ts, selected_metrics[sample.type_counter].name, sample.value, sample.name,
                (float)sample.value / sample.run_cnt, sample.run_cnt);
        fflush(stdout);
    }
    return 0;
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

    for (int i = 0; i < (selected_metrics_cnt * n_cpus); i++)
    {
        if (perf_event_fds[i] > 0)
            close(perf_event_fds[i]);
    }
    free(perf_event_fds);

    // close output file
    if (output_file)
        fclose(output_file);

    // set locale to print numbers with dot as thousands separator
    setlocale(LC_NUMERIC, "");

    if (enable_run_cnt)
    {
        // set locale to print numbers with dot as thousands separator
        // setlocale(LC_NUMERIC, "");

        // retrieve count fd
        int counts_fd = bpf_map__fd(profile_obj->maps.counts);
        if (counts_fd < 0)
        {
            fprintf(stderr, "[%s]: retrieving counts fd, runs was not counted\n", ERR);
            run_cnt = 0;
        }
        else
        {

            // retrieve count value
            __u64 counts[n_cpus];
            __u32 key = 0;
            int err = bpf_map_lookup_elem(counts_fd, &key, counts);
            if (err)
            {
                fprintf(stderr, "[%s]: retrieving run count\n", ERR);
            }

            for (int i = 0; i < n_cpus; i++)
            {
                run_cnt += counts[i];
                if (verbose && counts[i] > 0)
                {
                    fprintf(stdout, "\nCPU[%03d]: %'llu", i, counts[i]);
                }
            }
        }
        fprintf(stdout, "\nTotal run_cnt: %'llu     [N.CPUS: %d]\n", run_cnt, n_cpus);

        profiler__detach(profile_obj);
        profiler__destroy(profile_obj);
    }

    // print accumulated stats
    print_accumulated_stats();

    fprintf(stdout, "[%s]: Done \n", INFO);
    exit(0);
}

int attach_profiler(struct bpf_program *prog)
{
    int err;
    // this will be the profiler program
    struct bpf_program *prof_prog;
    if (!prog_name)
    {
        prog_name = (char *)bpf_program__name(prog);
    }

    bpf_object__for_each_program(prof_prog, profile_obj->obj)
    {
        err = bpf_program__set_attach_target(prof_prog, prog_fd, prog_name);
        if (err)
        {
            fprintf(stderr, "[%s]: setting attach target during profiler init\n", ERR);
            return 1;
        }
    }

    // load profiler
    err = profiler__load(profile_obj);
    if (err)
    {
        fprintf(stderr, "[%s]: loading profiler\n", ERR);
        return 1;
    }

    // attach profiler
    err = profiler__attach(profile_obj);
    if (err)
    {
        fprintf(stderr, "[%s]: attaching profiler\n", ERR);
        return 1;
    }

    return 0;
}

static void poll_stats(unsigned int map_fd, __u32 timeout_ns)
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
        sleep(timeout_ns / 1000);
    }
}

int main(int arg, char **argv)
{
    struct bpf_program *prog;
    int err, opt;

    // set shared var
    n_cpus = libbpf_num_possible_cpus();
    selected_metrics_cnt = 0;
    prog_name = NULL;
    info_len = sizeof(info);
    data = malloc(n_cpus * sizeof(struct record_array));
    array_map_fd = -1;

    // retrieve opt
    while ((opt = getopt(arg, argv, "e:n:o:P:acvsh")) != -1)
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
        case 'a':
            accumulate = 1;
            break;
        case 'c':
            enable_run_cnt = 1;
            break;
        case 'o':
            memcpy(output_filename, optarg, strlen(optarg));
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
    // start perf before loading prog
    err = start_perf(n_cpus); // perf fd will be freed during init_exit
    if (err)
    {
        init_exit(0);
        return 1;
    }
    // if enable_run_cnt is set, enable run count
    // open profile object
    if (enable_run_cnt)
    {
        profile_obj = profiler__open();
        if (!profile_obj)
        {
            fprintf(stderr, "[%s]: opening profile object\n", ERR);
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

    // start perf before loading prog
    err = start_perf(n_cpus); // perf fd will be freed during init_exit
    if (err)
    {
        init_exit(0);
        return 1;
    }

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
    if (selected_metrics_cnt > 0 && array_map_fd > 0)
    {
        // TODO - Using file as output instead stdout may not work properly
        // I either fixed the problem or I forgot what it was :)
        if (output_filename[0] != '\0')
        {
            output_file = fopen(output_filename, "w");
            if (output_file == NULL)
            {
                fprintf(stderr, "[%s]: during opening output file: %s\n", ERR, output_filename);
                init_exit(0);
                return 1;
            }
        }
        // start perf before polling
        poll_stats(array_map_fd, 1000);
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
