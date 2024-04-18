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
#include <mychardev.h>


// --- PRETTY PRINT -----
#define ERR "\033[1;31mERR\033[0m"
#define WARN "\033[1;33mWARN\033[0m"
#define INFO "\033[1;32mINFO\033[0m"
#define DEBUG "\033[1;34mDEBUG\033[0m"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MAX_METRICS 8
#define MAX_MEASUREMENT 16
#define PINNED_PATH "/sys/fs/bpf/"

struct section_stats
{
    __u64 acc_value;
    char name[16];
    __u64 run_cnt; // if the sections are sampled, we can count the runs

    // I don't need type counter attribute, this struct is used inside `profile_metric`
};

// metrics definition
struct profile_metric
{
    const char *name;
    // unused
    // struct bpf_perf_event_value val;
    struct section_stats *acc_persection;
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

struct bpf_object *obj;
int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
int verbose;
int perf_fd;
int load;
struct bpf_prog_info info;
__u32 info_len;
int prog_fd;
int prog_id;
char func_name[15];
char filename[256];
char *prog_name;
char *ifname;
int n_cpus;
int *perf_event_fds;
struct record_array *data;
int array_map_fd;
int firtst_offline_cpu;

// time variables
struct timespec start_running_time;
struct timespec end_running_time;
struct timespec delta;

int throw_away_events;

// plot
int do_plot;
struct gnuplot_cfg *plot_cfg;
int x_axis;

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
    printf("Usage: loader-stats -i <ifname> -f <filename> -m <mode>\n");
    printf("  -f <filename>        : BPF object file to load\n");
    printf("  -n <func name>       : XDP function name (only for programs already loaded)\n");
    printf("  -i <ifname>          : Interface name\n");
    printf("  -m <mode>            : xdp mode (skb, native)\n");
    // -P not work properly
    printf("  -P <prog_name>       : Program section name\n");
    printf("  -e <metrics>         : Comma separated list of metrics\n");
    printf("  -a                   : Accumulate stats\n");
    printf("  -c                   : Enable run count\n");
    printf("  -o <output_filename> : Output filename\n");
    printf("  -v                   : Verbose\n");
    printf("  -s                   : Supported metrics\n");
    printf("  -h                   : Print this help\n");
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
                    // I don't know if this is the best way to handle this
                    if (firtst_offline_cpu == -1)
                    {
                        firtst_offline_cpu = cpu;
                    }
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
    float percentage = 0;
    float avg_single_run = 0;

    fprintf(stdout, "\nAccumulated stats\n\n");
    for (int i = 0; i < selected_metrics_cnt; i++)
    {
        fprintf(stdout, "%s\n", selected_metrics[i].name);
        for (int s = 0; s < MAX_MEASUREMENT; s++)
        {
            if (strlen(selected_metrics[i].acc_persection[s].name) > 0)
            {

                if (enable_run_cnt)
                {
                    percentage = ((float)selected_metrics[i].acc_persection[s].run_cnt / run_cnt) * 100;
                }
                avg_single_run = (float)selected_metrics[i].acc_persection[s].acc_value /
                                 selected_metrics[i].acc_persection[s].run_cnt;

                fprintf(stdout, "[%s]: %s - %'llu runs\n", DEBUG, selected_metrics[i].acc_persection[s].name,
                        selected_metrics[i].acc_persection[s].run_cnt);
                fprintf(stdout, "    %s: %'llu      (%.2f%%)    avg: %2.f/pkt\n\n",
                        selected_metrics[i].acc_persection[s].name, selected_metrics[i].acc_persection[s].acc_value,
                        percentage, avg_single_run);
            }
            else
            {
                // here we can break the loop if we find a null section,
                // because the next sections will be null too
                break;
            }
        }
    }
}

void sub_timespec(struct timespec t1, struct timespec t2, struct timespec *td)
{
    td->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    td->tv_sec = t2.tv_sec - t1.tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0)
    {
        td->tv_nsec += NS_PER_SECOND;
        td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0)
    {
        td->tv_nsec -= NS_PER_SECOND;
        td->tv_sec++;
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

// accumulate stats
void accumulate_stats(struct record_array *sample)
{
    if (sample->type_counter >= selected_metrics_cnt)
    {
        return;
    }

    // find section if exists
    for (int s = 0; s < MAX_MEASUREMENT; s++)
    {
        // if the section is null, we can create a new one and stop the loop
        if (strlen(selected_metrics[sample->type_counter].acc_persection[s].name) == 0)
        {
            strcpy(selected_metrics[sample->type_counter].acc_persection[s].name, sample->name);
            selected_metrics[sample->type_counter].acc_persection[s].acc_value = sample->value;
            selected_metrics[sample->type_counter].acc_persection[s].run_cnt = sample->run_cnt;
            return;
        }

        // if the section exists, we can accumulate the value and stop the loop
        if (strcmp(sample->name, selected_metrics[sample->type_counter].acc_persection[s].name) == 0)
        {
            selected_metrics[sample->type_counter].acc_persection[s].acc_value = sample->value;
            selected_metrics[sample->type_counter].acc_persection[s].run_cnt = sample->run_cnt;
            return;
        }
    }

    return;
}

static int handle_event(struct record_array *data)
{
    struct record_array sample = {0};

    // accumulate for each cpu
    for (int cpu = 0; cpu < firtst_offline_cpu; cpu++)
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
    accumulate_stats(&sample);
    return 0;
}

static void init_exit(int sig)
{

    // read end timestamp
    clock_gettime(CLOCK_MONOTONIC, &end_running_time);
    sub_timespec(start_running_time, end_running_time, &delta);

    // consume remaining events
    if (selected_metrics_cnt)
    {
        for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
        {
            if (bpf_map_lookup_elem(array_map_fd, &key, data))
                continue;

            handle_event(data);
        }
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

    // print delta time
    fprintf(stdout, "[%s]: Elapsed time: %d.%09ld\n", INFO, (int)delta.tv_sec, delta.tv_nsec);
    // print delta time from loading

    if (info.run_time_ns > 0) // this work only with bpf_stats enabled
        fprintf(stdout, "[%s]: Elapsed time from loading: %d.%09lld\n", INFO, (int)info.run_time_ns / NS_PER_SECOND,
                info.run_time_ns % NS_PER_SECOND);

    if (run_cnt)
        fprintf(stdout, "[%s]: Troughtput: %d.%09lld\n", INFO, (int)(run_cnt / delta.tv_sec), run_cnt / delta.tv_nsec);

    // after read, free acc_persection
    for (int i = 0; i < selected_metrics_cnt; i++)
    {
        free(selected_metrics[i].acc_persection);
    }

    fprintf(stdout, "[%s]: Detaching program...\n", INFO);

    // if the program was loaded by this tool, detach it
    if (load)
    {
        int ifindex = if_nametoindex(ifname);
        if (ifindex == 0)
        {
            fprintf(stderr, "[%s]: getting ifindex during detaching\n", ERR);
        }
        else
        {
            // get in current prog id the xdp program attached to the interface
            // until we find a way to manage multiple prog id this is not working
            /*     if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id))
                {
                    printf("[ERR]: bpf_xdp_query_id failed\n");
                    exit(1);
                } */

            if (bpf_xdp_detach(ifindex, xdp_flags, NULL))
            {
                fprintf(stderr, "%s: bpf_xdp_detach failed\n", ERR);
            }
        }
    }

    // free plot_cfg
    if (do_plot)
    {
        gplot_close();
        free(plot_cfg);
    }

    bpf_object__close(obj);
    fprintf(stdout, "[%s]: Done \n", INFO);
    exit(0);
}

void moving_avg(FILE *file_data)
{
    time_t t;
    time(&t);
    struct tm *tm;
    char ts[32];
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    char value[16];
    char row[64];
    x_axis++;
    // add time to data
    snprintf(row, 64, "%d", x_axis);
    for (int s = 0; s < MAX_MEASUREMENT; s++)
    {
        for (int m = 0; m < selected_metrics_cnt; m++)
        {
            if (strlen(selected_metrics[m].acc_persection[s].name) != 0)
            {
                snprintf(value, sizeof(value), " %.2f",
                         (float)selected_metrics[m].acc_persection[s].acc_value /
                             selected_metrics[m].acc_persection[s].run_cnt);
                strcat(row, value);
            }
            else
            {
                break;
            }
        }
    }
    fprintf(file_data, "%s\n", row);
    fflush(file_data);
    return;
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

static int attach_prog(struct bpf_program *prog)
{
    int ifindex;
    int err;

    if (prog_name && strcmp(prog_name, bpf_program__name(prog)) != 0)
        return 0;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "[%s]: getting ifindex - ifname: %s \n", ERR, ifname);
        return 1;
    }

    // get prog fd
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
    {
        fprintf(stderr, "[%s]: retrieving prog fd\n", ERR);
        return 1;
    }

    if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0)
    {
        fprintf(stderr, "[%s]: attaching program - ifname: %s \n", ERR, ifname);
        return 1;
    }

    // TODO - find a way to manage multiple prog id
    // get prog id
    err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
    if (err)
    {
        // I'm not sure if strerror manage errno properly
        printf("[%s]: can't get prog info - %s\n", ERR, strerror(errno));
        return 1;
    }

    fprintf(stdout, "[%s]: Attached profiler\n", INFO);

    return 0;
}

static void poll_stats(unsigned int map_fd, __u32 timeout_ns)
{
    int err;

    time_t start_time = time(NULL);
    time_t current_time;

    // start plot process
    if (do_plot)
    {
        pid_t plot_pid = fork();
        if (plot_pid == 0) // CHILD PROCESS
        {
            // set default signal handler, otherwise the plot process calls init_exit
            signal(SIGINT, SIG_DFL);
            gplot_plot_poll();
            exit(0);
        }
        else if (plot_pid < 0)
        {
            fprintf(stderr, "[%s]: forking plot process\n", ERR);
            init_exit(0);
        }
    }

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
        if (do_plot)
        {
            current_time = time(NULL);
            if (current_time - start_time > plot_cfg->poll_interval)
            {
                moving_avg(plot_cfg->fp);
                start_time = current_time;
            }
        }
        sleep(timeout_ns / 1000);
    }
}

int main(int arg, char **argv)
{
    struct bpf_program *prog;
    int err, opt;

    // set shared var
    ifname = "\0";
    n_cpus = libbpf_num_possible_cpus();
    selected_metrics_cnt = 0;
    load = 0;
    prog_name = NULL;
    info_len = sizeof(info);
    plot_cfg = malloc(sizeof(struct gnuplot_cfg));
    data = malloc(n_cpus * sizeof(struct record_array));
    array_map_fd = -1;
    firtst_offline_cpu = -1;
    x_axis = 0;

    // retrieve opt
    while ((opt = getopt(arg, argv, ":m:P:f:n:i:e:ao:hsvcx")) != -1)
    {
        switch (opt)
        {
        // choosen xdp mode
        case 'm':
            if (strcmp(optarg, "skb") == 0)
            {
                xdp_flags |= XDP_FLAGS_SKB_MODE;
            }
            else
            {
                xdp_flags |= XDP_FLAGS_DRV_MODE;
            }
            break;
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
        case 'f':
            strcpy(filename, optarg);
            load = 1;
            break;
        case 'n':
            strcpy(func_name, optarg);
            break;
        case 'i':
            ifname = optarg;
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
        // find a appropriate name for this
        case 'x':
            do_plot = 1;
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

    // TODO: improve this
    // for loading filename and ifname are mandatory
    // for only stats prog_name is mandatory
    if (strlen(filename) == 0 && strlen(func_name) == 0)
    {
        fprintf(stderr, "[%s]: -f or -n is mandatory\n", ERR);
        return 1;
    }
    // check mutual exclusive opt
    if (strlen(filename) > 0 && strlen(func_name) > 0)
    {
        fprintf(
            stderr,
            "[%s]: -n is used to retrieve statistics from an already loaded program, use -l and -f to load a program\n",
            ERR);
        return 1;
    }

    // check mutual exclusive opt
    if (load && strlen(func_name) > 0)
    {
        fprintf(
            stderr,
            "[%s]: -n is used to retrieve statistics from an already loaded program, use -l and -f to load a program\n",
            ERR);
        return 1;
    }

    // if at least one metric is selected, allocate perf_event_fds
    if (selected_metrics_cnt > 0)
    {
        perf_event_fds = malloc((selected_metrics_cnt * n_cpus) * sizeof(int));
        for (int m = 0; m < selected_metrics_cnt; m++)
        {
            selected_metrics[m].acc_persection = malloc(MAX_MEASUREMENT * sizeof(struct section_stats));
            if (!selected_metrics[m].acc_persection)
            {
                fprintf(stderr, "[%s]: allocating memory for section stats\n", ERR);
                return 1;
            }
            selected_metrics[m].acc_persection->run_cnt = 0;
            selected_metrics[m].acc_persection->acc_value = 0;
            // define for safety
            selected_metrics[m].acc_persection->name[0] = '\0';
        }
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

    // load obj
    if (load)
    {
        // get obj
        obj = bpf_object__open_file(filename, NULL);
        if (libbpf_get_error(obj))
            return 1;

        // set prog type
        bpf_object__for_each_program(prog, obj)
        {
            err = bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
            if (err)
            {
                fprintf(stderr, "[%s]: setting program type\n", ERR);
                return 1;
            }
        }

        err = bpf_object__load(obj);
        if (err)
        {
            fprintf(stderr, "[%s]: loading object\n", ERR);
            return 1;
        }
    }

    // set trap for ctrl+c
    signal(SIGINT, init_exit);
    signal(SIGTERM, init_exit);

    fprintf(stdout, "[%s]: Loaded object...\n", INFO);

    // get ring buffer if at least one metric is selected
    if (selected_metrics_cnt > 0)
    {
        if (load)
        {
            array_map_fd = bpf_object__find_map_fd_by_name(obj, "percpu_output");
            if (array_map_fd < 0)
            {
                fprintf(stderr, "[%s]: finding map\nbe sure %s program own 'percpu_output' map", ERR, filename);
                return 1;
            }
        }
        else // if not loaded by this tool, retrieve map fd
        {
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
                fprintf(stderr, "[%s]: getting map fd from pinned path: %s\nbe sure %s program own 'percpu_output' map",
                        ERR, filename_map, func_name);
                return 1;
            }
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
    }

    // start perf before loading prog
    err = start_perf(n_cpus); // perf fd will be freed during init_exit
    if (err)
    {
        init_exit(0);
        return 1;
    }

    // if user wants plot, do it
    if (do_plot)
    {
        char *plot_filename = "/tmp/loader-stats-plot.data";
        char *plot_title = "Metrics";

        // plot config
        memcpy(plot_cfg->filename, plot_filename, strlen(plot_filename));
        memcpy(plot_cfg->title, plot_title, strlen(plot_title));
        plot_cfg->poll_interval = 1;

        time_t t;
        time(&t);

        // plot init
        err = gplot_init(plot_cfg);
        if (err || !plot_cfg->fp)
        {
            fprintf(stderr, "[%s]: initializing plot\n", ERR);
            init_exit(0);
            return 1;
        }

        fprintf(plot_cfg->fp, "1 1\n2 2\n");
        fflush(plot_cfg->fp);

        // see handle_event function for data writing
    }

    // do attach
    int i_prog = 0;
    if (load)
    {

        bpf_object__for_each_program(prog, obj)
        {
            // attach prog to interface and if enable_run_cnt is set, enable run count
            // attaching a fentry program

            err = attach_prog(prog);
            if (err)
            {
                init_exit(0);
                return 1;
            }
            if (enable_run_cnt)
            {
                err = attach_profiler(prog);
                if (err)
                {
                    init_exit(0);
                    return 1;
                }
            }
            i_prog++;
        }
    }
    else // if not loaded by this tool, retrieve prog fd
    {
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

        if (enable_run_cnt)
        {
            err = attach_profiler(prog);
            if (err)
            {
                init_exit(0);
                return 1;
            }
        }
        fprintf(stdout, "[%s]: Program name: %s\n", DEBUG, info.name);
    }

    // read first timestamp
    clock_gettime(CLOCK_MONOTONIC, &start_running_time);

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
