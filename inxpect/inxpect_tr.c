#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>

// if_nametoindex
#include <net/if.h>

#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// my modules
#include "inxpect.h"
#include "inxpect-server.h"
#include "mykperf_helpers.h"

struct event metrics[METRICS_NR] = {
    {.name = "instructions", .code = 0x00c0},          {.name = "cycles", .code = 0x003c},
    {.name = "cache-misses", .code = 0x412e},          {.name = "llc-misses", .code = 0x01b7},
    {.name = "L1-dcache-load-misses", .code = 0x0151},
};

// --- GLOBALS ---
char prog_name[MAX_PROG_FULL_NAME];
int prog_fd = -1;
struct psection_t psections[MAX_PSECTIONS];
int do_run_count = 0;
int timeout_s = 3;
int duration = 0;
int map_output_fd = -1;

// debug
__u64 *hist;

// threads
pthread_t thread_printer = {0};              // poll_print_stats
pthread_t threads_poll_stats[MAX_PSECTIONS]; // poll_stats
int duration;

// percpu map
int do_accumulate = 0;

// multiplexed map
struct record *mmap_map = NULL;
int multiplexed_mode = 0;
int multiplex_rate = 0;

// events
char *arg__event = NULL;
char *selected_events[MAX_METRICS];
int nr_selected_events = 0;
int running_cpu = -1;
int sample_rate = 0;

// server
int interactive_mode = 0;

static size_t roundup_page(size_t sz)
{
    long page_size = sysconf(_SC_PAGE_SIZE);
    return (sz + page_size - 1) / page_size * page_size;
}

// from bpftool
static int prog_fd_by_nametag(char nametag[MAX_PROG_FULL_NAME])
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

static int psections__get_list(char psections_name_list[MAX_PSECTIONS][MAX_PROG_FULL_NAME])
{
    int fd = -1;
    int zero = 0;
    fd = get_rodata_map_fd(prog_fd);
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding rodata map\n", ERR);
        return -1;
    }

    struct bpf_map_info info = {0};
    int info_len = sizeof(info);

    int err = bpf_map_get_info_by_fd(fd, &info, &info_len);
    if (err)
    {
        fprintf(stderr, "[%s]: during getting map rodata info: %s\n", ERR, strerror(errno));
        return -1;
    }

    // TODO: check this part, could be dangerous
    unsigned char *buffer = calloc(info.value_size, sizeof(unsigned char));
    err = bpf_map_lookup_elem(fd, &zero, buffer);
    if (err)
    {
        fprintf(stderr, "[%s]: during profiler section name retrieve\n", ERR);
        free(buffer);
        return -1;
    }

    // parse the part of the buffer that contains the sections
    struct rodata *rodata = (struct rodata *)buffer;
    // struct rodata *rodata = calloc(1, sizeof(struct rodata));
    //  memcpy(rodata, buffer, sizeof(struct rodata));
    // rodata = (struct rodata *)buffer;

    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (rodata->sections[i][0] == '\0')
        {
            printf("\nrodata: %d\n", i);
            break;
        }
        strncpy(psections_name_list[i], rodata->sections[i], sizeof(rodata->sections[i]));
    }

    free(buffer);
    // free(rodata);
    return 0;
}

static int run_count__get()
{
    int fd = -1;
    int zero = 0;
    fd = get_bss_map_fd(prog_fd);
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding bss map\n", ERR);
        return -1;
    }

    struct bss bss_data = {0};

    int err = bpf_map_lookup_elem(fd, &zero, &bss_data);
    if (err)
    {
        fprintf(stderr, "[%s]: during getting run count\n", ERR);
        return -1;
    }

    close(fd);
    return bss_data.run_cnt;
}

static int multiplex__set_rate(int multiplex_rate)
{
    int fd = -1;
    int zero = 0;
    fd = get_data_map_fd(prog_fd);
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding data map\n", ERR);
        return -1;
    }

    struct bpf_map_info info = {0};
    int info_len = sizeof(info);

    int err = bpf_map_get_info_by_fd(fd, &info, &info_len);
    if (err)
    {
        fprintf(stderr, "[%s]: during getting map data info: %s\n", ERR, strerror(errno));
        return -1;
    }

    // TODO: check this part, could be dangerous
    unsigned char *buffer = calloc(info.value_size, sizeof(unsigned char));
    err = bpf_map_lookup_elem(fd, &zero, buffer);
    if (err)
    {
        fprintf(stderr, "[%s]: during data retrieve\n", ERR);
        free(buffer);
        return -1;
    }

    struct data *data = malloc(sizeof(struct data));
    memcpy(data, buffer, sizeof(buffer));
    free(buffer);

    data->multiplex_rate = multiplex_rate;

    err = bpf_map_update_elem(fd, &zero, data, BPF_ANY);
    if (err)
    {
        fprintf(stderr, "[%s]: during updating data map\n", ERR);
        free(data);
        return -1;
    }
    free(data);
    return 0;
}

static int multiplex__set_num_counters(const __u8 num_counters)
{
    int fd = -1;
    int zero = 0;
    fd = get_data_map_fd(prog_fd);
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding data map\n", ERR);
        return -1;
    }

    struct bpf_map_info info = {0};
    int info_len = sizeof(info);

    int err = bpf_map_get_info_by_fd(fd, &info, &info_len);
    if (err)
    {
        fprintf(stderr, "[%s]: during getting map data info: %s\n", ERR, strerror(errno));
        return -1;
    }

    // TODO: check this part, could be dangerous
    unsigned char *buffer = calloc(info.value_size, sizeof(unsigned char));
    err = bpf_map_lookup_elem(fd, &zero, buffer);
    if (err)
    {
        fprintf(stderr, "[%s]: during data retrieve\n", ERR);
        free(buffer);
        return -1;
    }

    struct data *data = malloc(sizeof(struct data));
    memcpy(data, buffer, sizeof(buffer));

    data->num_counters = num_counters;

    err = bpf_map_update_elem(fd, &zero, data, BPF_ANY);
    if (err)
    {
        fprintf(stderr, "[%s]: during updating data map\n", ERR);
        free(buffer);
        free(data);
        return -1;
    }
    free(buffer);
    free(data);
    return 0;
}

static int percpu_output__get_fd()
{
    char filename_map[256];
    int err = snprintf(filename_map, sizeof(filename_map), "%s%s", PINNED_PATH, PERCPU_OUTPUT);
    if (err < 0)
    {
        fprintf(stderr, "[%s]: creating filename for pinned path: %s\n", ERR, strerror(errno));
        return -1;
    }

    // retrieve map fd from pinned path
    int map_fd = bpf_obj_get(filename_map);
    if (map_fd < 0)
    {
        fprintf(stderr, "[%s]: getting map fd from pinned path: %s\nbe sure %s program own '%s' map", ERR, filename_map,
                prog_name, PERCPU_OUTPUT);
        return -1;
    }

    return map_fd;
}

static int multiplexed_output__get_fd()
{
    char filename_map[256];
    int err = snprintf(filename_map, sizeof(filename_map), "%s%s", PINNED_PATH, MULTIPLEXED_OUTPUT);
    if (err < 0)
    {
        fprintf(stderr, "[%s]: creating filename for pinned path: %s\n", ERR, strerror(errno));
        return -1;
    }

    // retrieve map fd from pinned path
    int map_fd = bpf_obj_get(filename_map);
    if (map_fd < 0)
    {
        fprintf(stderr, "[%s]: getting map fd from pinned path: %s\nbe sure %s program own '%s' map", ERR, filename_map,
                prog_name, MULTIPLEXED_OUTPUT);
        return -1;
    }

    // mmap the map
    mmap_map = mmap(NULL, roundup_page(sizeof(struct record_array) * MAX_ENTRIES_PERCPU_ARRAY), PROT_READ | PROT_WRITE,
                    MAP_SHARED, map_fd, 0);
    if (mmap_map == MAP_FAILED)
    {
        fprintf(stderr, "[%s]: during mmap the map\n", ERR);
        return -1;
    }

    return map_fd;
}

static void print_stats()
{
    char *fmt = "   %s: %llu   %.2f/pkt - %u run_cnt\n";
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (!psections[i_sec].record)
        {
            break;
        }

        fprintf(stdout, "%s\n", psections[i_sec].record->name);
        for (int j = 0; j < MAX_METRICS; j++)
        {
            if (!psections[i_sec].metrics[j])
            {
                continue;
            }
            fprintf(stdout, fmt, psections[i_sec].metrics[j]->name, psections[i_sec].record->values[j],
                    (float)psections[i_sec].record->values[j] / psections[i_sec].record->run_cnts[j],
                    psections[i_sec].record->run_cnts[j]);
        }
    }
}

static void poll_print_stats()
{
    char *fmt = "   - %s: %llu   %.2f/pkt - %u run_cnt\n";
    while (1)
    {
        for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
        {
            if (!psections[i_sec].record)
            {
                break;
            }

            fprintf(stdout, "%s:\n", psections[i_sec].record->name);
            for (int j = 0; j < nr_selected_events; j++)
            {
                fprintf(stdout, fmt, psections[i_sec].metrics[j]->name, psections[i_sec].record->values[j],
                        (float)psections[i_sec].record->values[j] / psections[i_sec].record->run_cnts[j],
                        psections[i_sec].record->run_cnts[j]);
            }
        };
        sleep(timeout_s);
    }
}

static void poll_stats(const int key) // key is the id thread
{

    int err;
    __u64 values[MAX_METRICS];
    __u64 run_cnts[MAX_METRICS];

    struct record thread_stats;
    __u64 diff = 0;
    while (1)
    {
        thread_stats = mmap_map[key];

        // reset values and run_cnts
        memset(values, 0, sizeof(values));
        memset(run_cnts, 0, sizeof(run_cnts));

        // I don't know if check run_cnts[0] is the right thing to do
        if (thread_stats.name[0] == '\0' || thread_stats.run_cnts[0] == 0)
            continue;

        for (int i = 0; i < MAX_METRICS; i++)
        {
            values[i] += thread_stats.values[i];
            run_cnts[i] += thread_stats.run_cnts[i];
            if (thread_stats.run_cnts[0] >= psections[key].record->run_cnts[0])
            {
                diff = thread_stats.run_cnts[0] - psections[key].record->run_cnts[0];
                // make hist
                if (diff > 254)
                {
                    hist[254]++;
                }
                else
                {
                    hist[diff]++;
                }
            }
        }

        memcpy(psections[key].record->values, values, sizeof(values));
        memcpy(psections[key].record->run_cnts, run_cnts, sizeof(run_cnts));

        // usleep(10000);
    }
}

static void exit_cleanup(int signo)
{
    if (interactive_mode)
        inxpect_server__close();

    if (!do_accumulate && thread_printer)
        pthread_cancel(thread_printer);

    // kill threads poll stats
    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (!psections[i].record)
        {
            break;
        }
        if (threads_poll_stats[i])
            pthread_cancel(threads_poll_stats[i]);
    }

    print_stats();

    int err;
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (!psections[i_sec].record)
        {
            break;
        }

        for (int j = 0; j < MAX_METRICS; j++)
        {
            if (!psections[i_sec].metrics[j])
            {
                continue;
            }

            if (psections[i_sec].metrics[j]->enabled)
            {
                err = event__disable(psections[i_sec].metrics[j], running_cpu);
                if (err)
                {
                    fprintf(stderr, "[%s]: during disabling event %s\n", ERR, psections[i_sec].metrics[j]->name);
                }

                psections[i_sec].metrics[j] = NULL;
            }
        }

        // -------- FREE ALLOC IN PSECTIONS --------
        if (psections[i_sec].record)
            free(psections[i_sec].record);
    }
    if (selected_events[0] != NULL)
        for (int i = 0; i < nr_selected_events--; i++)
        {
            if (selected_events[i])
                free(selected_events[i]);
        }

    printf("\n");

    // mean value
    __u64 sum = 0;
    __u64 count = 0;
    for (int i = 0; i < 256; i++)
    {
        printf("%llu,", hist[i]);
        sum += (__u64)hist[i] * (__u64)i;
        count += hist[i];
    }

    printf("\n");

    printf("sum: %llu\n", sum);
    printf("count: %llu\n", count);

    printf("mean: %.2f\n", (double)sum / count);

    free(hist);

    fprintf(stdout, "[%s]: exiting\n", DEBUG);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int err, opt;
    // retrieve opt
    while ((opt = getopt(argc, argv, "n:e:C:s:t:r:d:aic")) != -1)
    {
        switch (opt)
        {
        case 'n':
            if (strlen(optarg) > MAX_PROG_FULL_NAME)
            {
                fprintf(stderr, "%s: program name too long, should be no longer then %d characters\n", ERR,
                        MAX_PROG_FULL_NAME);
                exit_cleanup(0);
            }
            strcpy(prog_name, optarg);
            break;
        case 'e':
            // arg_event = instructions,cycles,...
            arg__event = strtok(optarg, ",");
            while (arg__event != NULL)
            {
                selected_events[nr_selected_events] = malloc(strlen(arg__event) + 1);
                strcpy(selected_events[nr_selected_events], arg__event);
                nr_selected_events++;
                arg__event = strtok(NULL, ",");
            }
            break;
        case 'C':
            running_cpu = atoi(optarg);
            break;
        case 't':
            timeout_s = atoi(optarg);
            break;
        case 's':
            sample_rate = atoi(optarg);
            break;
        case 'c':
            do_run_count = 1;
            break;
        case 'd':
            duration = atoi(optarg);
            break;
        case 'r':
            multiplexed_mode = 1; // not used
            multiplex_rate = atoi(optarg);
            // multiplex rate can not be setted here because the prog fd is not yet retrieved
            break;
        case 'a':
            do_accumulate = 1;
            break;
        case 'i':
            interactive_mode = 1;
            break;
        case '?':
            fprintf(stderr, "%s: invalid option\n", ERR);
            exit_cleanup(0);
            break;
        }
    }

    hist = malloc(256 * sizeof(__u64));

    for (int i = 0; i < 256; i++)
    {
        hist[i] = (__u64)0;
    }

    // ---------- ARGS CHECKS ----------
    // TODO: check any error
    if (strlen(prog_name) == 0)
    {
        fprintf(stderr, "[%s]: program name is required\n", ERR);
        exit_cleanup(0);
    }

    if (!nr_selected_events)
    {
        fprintf(stderr, "[%s]: event name is required\n", ERR);
        exit_cleanup(0);
    }

    if (running_cpu >= libbpf_num_possible_cpus())
    {
        fprintf(stderr, "[%s]: cpu %d is not valid\n", ERR, running_cpu);
        exit_cleanup(0);
    }

    if ((sample_rate && !do_run_count) || (!sample_rate && do_run_count))
    {
        fprintf(stderr,
                "[%s]: sample rate and run count should be set together, otherwise will not be possible to calculate "
                "the correct rate\n",
                WARN);
    }

    if (duration && interactive_mode)
    {
        fprintf(stdout, "[%s]: duration and interactive mode are mutually exclusive\n   Duration will have priority",
                WARN);
    }

    // ------------------------------------------------

    // retrieve `prog_name` file descriptor by name
    prog_fd = prog_fd_by_nametag(prog_name);
    if (prog_fd < 0)
    {
        fprintf(stderr, "[%s]: can't get prog fd by name: %s\n", ERR, strerror(errno));
        exit_cleanup(0);
    }

    // at this point the we are sure that the program is loaded

    if (multiplex_rate)
    {
        err = multiplex__set_rate(multiplex_rate);
        if (err)
            exit_cleanup(0); // check this, I think will be not safe
    }

    // retrieve the psection from xdp program
    char psections_name_list[MAX_PSECTIONS][MAX_PROG_FULL_NAME] = {0};
    err = psections__get_list(psections_name_list);
    if (err)
    {
        fprintf(stderr, "[%s]: during psections list retrieve\n", ERR);
        exit_cleanup(0);
    }

    // setting psections
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (psections_name_list[i_sec][0] == '\0')
        {
            psections[i_sec].record = NULL;
            break;
        }

        // alloc memory for the record
        psections[i_sec].record = calloc(1, sizeof(struct record));
        if (!psections[i_sec].record)
        {
            fprintf(stderr, "[%s]: during memory allocation\n", ERR);
            exit_cleanup(0);
        }

        for (int i = 0; i < nr_selected_events; i++)
        {
            // manage events
            struct event *metric = NULL;

            if (selected_events[i][0] == 'r') // if the event is a raw event
            {
                metric = malloc(sizeof(struct event));
                struct event tmp_metric = {
                    .name = selected_events[i],
                    .code = atoi(selected_events[i] + 1),
                };

                memcpy(metric, &tmp_metric, sizeof(struct event));
            }
            else // otherwise is a perf event
            {
                metric = event__get_by_name(selected_events[i]);
                if (!metric)
                {
                    fprintf(stderr, "[%s]: event %s not found\n", ERR, metric->name);
                    exit_cleanup(0);
                }
            }

            strcpy(psections[i_sec].record->name, psections_name_list[i_sec]);

            // enable the event
            err = event__enable(metric, running_cpu);
            if (err)
            {
                fprintf(stderr, "[%s]: during enabling event %s\n", ERR, metric->name);
                exit_cleanup(0);
            }

            // set to the psection the related event
            psections[i_sec].metrics[i] = metric;

            psections[i_sec].record->counters[(i % 4)] = psections[i_sec].metrics[i]->reg_h;
        }
    }

    if (sample_rate)
    {
        err = sample_rate__set(prog_fd, sample_rate);
        if (err)
            exit_cleanup(0);
    }

    /*     // retrieve percpu_output fd
        map_output_fd = percpu_output__get_fd();
        if (map_output_fd < 0)
        {
            exit_cleanup(0);
        } */

    map_output_fd = multiplexed_output__get_fd();
    if (map_output_fd < 0)
    {
        exit_cleanup(0);
    }

    // set signal handler
    signal(SIGINT, exit_cleanup);
    signal(SIGTERM, exit_cleanup);
    if (duration)
        signal(SIGALRM, exit_cleanup);

    err = multiplex__set_num_counters(nr_selected_events);
    if (err)
        exit_cleanup(0);

    err = percput_output__clean_and_init(map_output_fd, running_cpu);
    if (err)
        exit_cleanup(0);

    err = run_count__reset(prog_fd);
    if (err)
        fprintf(stderr, "[%s]: during run count reset\n", WARN);

    if (!do_accumulate)
        pthread_create(&thread_printer, NULL, (void *)poll_print_stats, NULL);

    for (int thread_id = 0; thread_id < MAX_PSECTIONS; thread_id++)
    {
        // if the record is NULL, we are at the end of the list and we avoid to create a thread
        if (!psections[thread_id].record)
        {
            break;
        }
        pthread_create(&threads_poll_stats[thread_id], NULL, (void *)poll_stats, thread_id);
    }

    alarm(duration);

    if (interactive_mode) // SERVER
    {
        err = inxpect_server__init_server(0); // port = 0 -> default 8080 port
        if (err)
        {
            exit_cleanup(0);
        }

        err = inxpect_server__start_and_polling();
        if (err)
        {
            exit_cleanup(0);
        }
    }
    else
    {
        pause(); // wait for signal
    }

    exit_cleanup(0);
    return 0;
}