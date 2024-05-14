#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

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
    {.name = "L1-icache-load-misses", .code = 0x0283},
};

// --- GLOBALS ---
char prog_name[MAX_PROG_FULL_NAME];
struct psection_t psections[MAX_PSECTIONS];
int do_run_count = 0;
int timeout_s = 3;
int prog_fd = -1;

// threads
pthread_t thread_printer;                    // poll_print_stats
pthread_t threads_poll_stats[MAX_PSECTIONS]; // poll_stats

// percpu map
int percpu_output_fd = -1;
struct record_array *percpu_data;
int do_accumulate = 0;

// events
char *arg__event = NULL;
int nr_selected_events = 0;
int running_cpu = 0;
int sample_rate = 0;

// server
int interactive_mode = 0;
pid_t server_process = -1;

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

        fprintf(stderr, "[%s]: during finding data map\n", ERR);
        return -1;
    }

    struct rodata bss_data = {0};

    int err = bpf_map_lookup_elem(fd, &zero, &bss_data);
    if (err)
    {
        fprintf(stderr, "[%s]: during profiler section name retrieve\n", ERR);
        return -1;
    }

    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (bss_data.sections[i][0] == 0)
        {
            break;
        }
        strncpy(psections_name_list[i], bss_data.sections[i], sizeof(bss_data.sections[i]));
        fprintf(stderr, "Found section: %s\n", psections_name_list[i]);
    }

    close(fd);
    return 0;
}

static int run_count__get()
{
    int fd = -1;
    int zero = 0;
    fd = get_bss_map_fd(prog_fd);
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding data map\n", ERR);
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

static int run_count__reset()
{
    int fd = -1;
    int zero = 0;
    fd = get_bss_map_fd(prog_fd);
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding data map\n", ERR);
        return -1;
    }

    struct bss bss_data = {0};

    int err = bpf_map_lookup_elem(fd, &zero, &bss_data);
    if (err)
    {
        fprintf(stderr, "[%s]: during getting run count\n", ERR);
        return -1;
    }

    bss_data.run_cnt = 0;

    err = bpf_map_update_elem(fd, &zero, &bss_data, BPF_ANY);
    if (err)
    {
        fprintf(stderr, "[%s]: during setting run count\n", ERR);
        return -1;
    }

    close(fd);
    return 0;
}

static int percpu_output__get_fd()
{
    char filename_map[256];
    int err = snprintf(filename_map, sizeof(filename_map), "%s%s", PINNED_PATH, RECORD_MAP_NAME);
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
                prog_name, RECORD_MAP_NAME);
        return -1;
    }

    return map_fd;
}

static int percput_output__clean_and_init()
{
    int err;
    /*    unsigned int count = MAX_PSECTIONS;
       int *keys = malloc(MAX_PSECTIONS * sizeof(int));
       // clean the map
       int err = bpf_map_delete_batch(percpu_output_fd, keys, &count, NULL);
       if (err)
       {
           fprintf(stderr, "[%s]: during cleaning map: %s\n", ERR, strerror(errno));
           fprintf(stderr, "[%s]: %d\n", DEBUG, count);
           free(keys);
           return -1;
       }
       free(keys);
    */

    // init the map
    int nr_cpus = libbpf_num_possible_cpus();
    struct record_array *percpu_values = calloc(nr_cpus, sizeof(struct record_array));

    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (!psections[i_sec].record)
        {
            break;
        }

        percpu_values[running_cpu] = *psections[i_sec].record;

        err = bpf_map_update_elem(percpu_output_fd, &i_sec, percpu_values, BPF_ANY);
        if (err)
        {
            fprintf(stderr, "[%s]: during updating map\n", ERR);
            free(percpu_values);
            return -1;
        }
    }

    err = run_count__reset();
    if (err)
    {
        free(percpu_values);
        return -1;
    }

    free(percpu_values);

    return 0;
}

static void print_stats()
{
    char *fmt = "%s: %llu   %.2f/pkt - %u run_cnt\n";
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (!psections[i_sec].record)
        {
            break;
        }

        fprintf(stdout, fmt, psections[i_sec].record->name, psections[i_sec].record->value,
                (float)psections[i_sec].record->value / psections[i_sec].record->run_cnt,
                psections[i_sec].record->run_cnt);
    }
}

static void poll_print_stats()
{
    char *fmt = "%s: %llu   %.2f/pkt - %u run_cnt\n";
    int prev_run_count = 0;
    int prev_value = 0;
    while (1)
    {
        for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
        {
            if (!psections[i_sec].record)
            {
                break;
            }

            if (prev_run_count != psections[i_sec].record->run_cnt)
            {
                fprintf(stdout, "%sdiff: value: %lld   %f/pkt    run_count: %lld\n", ERR,
                        (psections[i_sec].record->value - prev_value),
                        (float)(psections[i_sec].record->value - prev_value) /
                            (psections[i_sec].record->run_cnt - prev_run_count),
                        psections[i_sec].record->run_cnt - prev_run_count);

                prev_run_count = psections[i_sec].record->run_cnt;
                prev_value = psections[i_sec].record->value;

                fprintf(stdout, fmt, psections[i_sec].record->name, psections[i_sec].record->value,
                        (float)psections[i_sec].record->value / psections[i_sec].record->run_cnt,
                        psections[i_sec].record->run_cnt);
            }
            /*          fprintf(stdout, fmt, psections[i_sec].record->name, psections[i_sec].record->value,
                             (float)psections[i_sec].record->value / psections[i_sec].record->run_cnt,
                             psections[i_sec].record->run_cnt); */
        };
        // usleep(1000000);
    }
}

static void poll_stats(int key) // key is the id thread
{
    int err;
    struct record_array thread_stats[libbpf_num_possible_cpus()];
    while (1)
    {
        err = bpf_map_lookup_elem(percpu_output_fd, &key, thread_stats);
        if (err)
        {
            continue;
        }
        for (int cpu = 0; cpu < libbpf_num_possible_cpus(); cpu++)
        {
            if (thread_stats[cpu].name[0] == '\0')
                continue;

            // TODO: not work with more than 1 cpu
            psections[key].record->value = thread_stats[cpu].value;
            psections[key].record->run_cnt = thread_stats[cpu].run_cnt;
        }
        // usleep(10000);
    }
}

static void exit_cleanup(int signo)
{
    if (interactive_mode)
        inxpect_server__close();

    if (!do_accumulate)
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

    // get the last not yet readed events
    for (int key = 0; key < MAX_ENTRIES_PERCPU_ARRAY; key++)
    {
        if (!psections[key].record)
        {
            break;
        }

        if (bpf_map_lookup_elem(percpu_output_fd, &key, percpu_data) < 0)
        {
            continue;
        }
        for (int cpu = 0; cpu < libbpf_num_possible_cpus(); cpu++)
        {
            if (percpu_data[cpu].name[0] == '\0')
                continue;

            psections[key].record->value = percpu_data[cpu].value;
            psections[key].record->run_cnt = percpu_data[cpu].run_cnt;
        }
    }
    print_stats();

    int err;
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (!psections[i_sec].record)
        {
            break;
        }

        if (psections[i_sec].metric->enabled)
        {
            err = event__disable(psections[i_sec].metric, running_cpu);
            if (err)
            {
                fprintf(stderr, "[%s]: during disabling event %s\n", ERR, psections[i_sec].metric->name);
            }
        }

        // -------- FREE ALLOC IN PSECTIONS --------
        free(psections[i_sec].record);
    }

    if (arg__event)
        free(arg__event);

    fprintf(stdout, "[%s]: exiting\n", DEBUG);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
    int err, opt;
    // retrieve opt
    while ((opt = getopt(argc, argv, ":n:e:C:s:t:aic")) != -1)
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
            arg__event = malloc(strlen(optarg) + 1);
            strcpy(arg__event, optarg);
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

    percpu_data = malloc(libbpf_num_possible_cpus() * sizeof(struct record_array));

    // ---------- ARGS CHECKS ----------
    // TODO: check any error
    if (strlen(prog_name) == 0)
    {
        fprintf(stderr, "[%s]: program name is required\n", ERR);
        exit_cleanup(0);
    }

    if (arg__event == NULL)
    {
        fprintf(stderr, "[%s]: event name is required\n", ERR);
        exit_cleanup(0);
    }

    if (!event__name_isvalid(arg__event))
    {
        fprintf(stderr, "[%s]: event name %s is not valid\n", ERR, arg__event);
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

    // ------------------------------------------------

    // retrieve `prog_name` file descriptor by name
    prog_fd = prog_fd_by_nametag(prog_name);
    if (prog_fd < 0)
    {
        fprintf(stderr, "[%s]: can't get prog fd by name: %s\n", ERR, strerror(errno));
        exit_cleanup(0);
    }

    // at this point the we are sure that the program is loaded

    // retrieve the psection from xdp program
    char psections_name_list[MAX_PSECTIONS][MAX_PROG_FULL_NAME];
    err = psections__get_list(psections_name_list);
    if (err)
    {
        fprintf(stderr, "[%s]: during psections list retrieve\n", ERR);
        exit_cleanup(0);
    }

    // setting psections
    for (int i_sec = 0; i_sec < MAX_PSECTIONS; i_sec++)
    {
        if (strlen(psections_name_list[i_sec]) == 0)
        {
            psections[i_sec].record = NULL;
            break;
        }

        // alloc memory for the record
        psections[i_sec].record = malloc(sizeof(struct record_array));
        if (!psections[i_sec].record)
        {
            fprintf(stderr, "[%s]: during memory allocation\n", ERR);
            exit_cleanup(0);
        }

        struct event *metric = event__get_by_name(arg__event);
        if (!metric)
        {
            fprintf(stderr, "[%s]: event %s not found\n", ERR, arg__event);
            exit_cleanup(0);
        }

        strcpy(psections[i_sec].record->name, psections_name_list[i_sec]);

        // enable the event
        err = event__enable(metric, running_cpu);
        if (err)
        {
            fprintf(stderr, "[%s]: during enabling event %s\n", ERR, arg__event);
            exit_cleanup(0);
        }

        // set to the psection the related event
        psections[i_sec].metric = metric;

        // set the event to the record array
        psections[i_sec].record->counter = psections[i_sec].metric->reg_h;

        // TODO: currently reg_h is the counter, so we can use it. But I want to store the index register, so in
        // future this should be reg_h - MAX REGISETR
    }

    if (sample_rate)
    {
        err = sample_rate__set(sample_rate);
        if (err)
            exit_cleanup(0);
    }

    // retrieve percpu_output fd
    percpu_output_fd = percpu_output__get_fd();
    if (percpu_output_fd < 0)
    {
        exit_cleanup(0);
    }

    // set signal handler
    signal(SIGINT, exit_cleanup);
    signal(SIGTERM, exit_cleanup);

    err = percput_output__clean_and_init();
    if (err)
        exit_cleanup(0);

    if (!do_accumulate)
        pthread_create(&thread_printer, NULL, poll_print_stats, NULL);

    for (int thead_id = 0; thead_id < MAX_PSECTIONS; thead_id++)
    {
        // if the record is NULL, we are at the end of the list and we avoid to create a thread
        if (!psections[thead_id].record)
        {
            break;
        }
        pthread_create(&threads_poll_stats[thead_id], NULL, poll_stats, thead_id);
    }

    if (interactive_mode) // SERVER
    {
        err = inxpect_server__init_server(0); // port = 0 -> defaul 8080 port
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
