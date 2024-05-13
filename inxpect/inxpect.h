#ifndef __INXPECT_H__
#define __INXPECT_H__

#include "mykperf_module.h"
#include "mykperf_helpers.h"

// --- PRETTY PRINT -----
#define ERR "\033[1;31mERR\033[0m"
#define WARN "\033[1;33mWARN\033[0m"
#define INFO "\033[1;32mINFO\033[0m"
#define DEBUG "\033[1;34mDEBUG\033[0m"

// #define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
//  this is needed because of the way the metrics are defined
// ARRAY SIZE not work with extern
#define METRICS_NR 5

#define MAX_METRICS 8
#define MAX_PSECTIONS 8
#define PINNED_PATH "/sys/fs/bpf/"
#define RECORD_MAP_NAME "percpu_output"

#define MAX_PROG_FULL_NAME 15

struct event
{
    const char *name;
    const __u64 code;
    int cpu; // now, work with just one cpu
    int reg_h;
    __u8 enabled;
};

extern struct event metrics[];

struct psection_t
{
    struct record_array *record;
    struct event *metric;
};

// ---- EVENT ----------
static struct event *event__get_by_name(const char *name)
{
    for (int i = 0; i < METRICS_NR; i++)
    {
        if (strcmp(metrics[i].name, name) == 0)
        {
            return &metrics[i];
        }
    }
    return NULL;
}

static int event__enable(struct event *event, int cpu)
{
    int err = enable_event(event->code, &event->reg_h, cpu);
    if (err)
    {
        return -1;
    }
    fprintf(stdout, "[%s]:   %s: %x\n", DEBUG, event->name, event->reg_h);
    event->cpu = cpu;
    event->enabled = 1;
    return 0;
}

static int event__disable(struct event *event, int cpu)
{
    int err = disable_event(event->code, event->reg_h, cpu);
    if (err)
    {
        return -1;
    }
    event->enabled = 0;
    return 0;
}

static int event__name_isvalid(char *name)
{
    for (int i = 0; i < METRICS_NR; i++)
    {
        if (strcmp(metrics[i].name, name) == 0)
        {
            return 1;
        }
    }
    return 0;
}

// -------------------------------------

// ---------------- PSECTIONS ----------

extern struct psection_t psections[];
static struct psection_t *psection__get_by_name(const char *name)
{
    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (strcmp(psections[i].record->name, name) == 0)
        {
            return &psections[i];
        }
    }
    return NULL;
}

static int psection__change_event(struct psection_t *psection, const char *event_name)
{
    struct event *event = event__get_by_name(event_name);
    if (!event)
    {
        return -1;
    }
    if (!event->enabled)
    {
        int err = event__enable(event, event->cpu);
        if (err)
        {
            return -1;
        }
    }
    psection->metric = event;
    return 0;
}

static int psection__event_disable(struct psection_t *psection)
{
    if (!psection->metric)
    {
        return 0;
    }

    if (psection->metric->enabled == 1)
    {
        int err = event__disable(psection->metric, psection->metric->cpu);
        if (err)
        {
            return -1;
        }
        return 0;
    }

    psection->metric->enabled--;
    psection->metric = NULL;
    return 0;
}

static int psection__set_event(struct psection_t *psection, struct event *event)
{
    if (psection->metric)
    {
        psection__event_disable(psection);
    }

    if (!event->enabled)
    {
        int err = event__enable(event, event->cpu);
        if (err)
        {
            return -1;
        }
    }
    else
    {
        event->enabled++; // count how much psections are using this event
    }
    psection->metric = event;
    return 0;
}

// get all psection in json
static void psection__get_all(char *json)
{
    json[0] = '[';
    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (psections[i].record)
        {
            strcat(json, psections[i].record->name);
            strcat(json, ",");
        }
    }
    json[strlen(json) - 1] = ']';
}

// ----------- SAMPLE RATE -----------------
static int sample_rate__set(int sample_rate)
{
    int fd = -1;
    int zero = 0;
    fd = get_bss_map_fd();
    if (fd < 0)
    {
        fprintf(stderr, "[%s]: during finding data map\n", ERR);
        return -1;
    }

    struct bss bss_data = {0};

    int err = bpf_map_lookup_elem(fd, &zero, &bss_data);
    if (err)
    {
        fprintf(stderr, "[%s]: during setting sample rate\n", ERR);
        return -1;
    }

    bss_data.__sample_rate = sample_rate;

    err = bpf_map_update_elem(fd, &zero, &bss_data, BPF_ANY);
    if (err)
    {
        fprintf(stderr, "[%s]: during setting sample rate\n", ERR);
        return -1;
    }

    close(fd);
    return 0;
}

// -------------------------------------------------

// ------------------- DATA -----------------------
static struct record_array *stats__get_by_psection_name(char *name)
{
    struct psection_t *psection = psection__get_by_name(name);
    if (!psection)
    {
        return -1;
    }
    return psection->record;
}
#endif // __INXPECT_H__