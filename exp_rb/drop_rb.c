#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include "drop_rb.skel.h"

int if_index;
struct drop_rb_bpf *drop_rb;
struct ring_buffer *rb;

void sig_handler(int sig)
{
    ring_buffer__free(rb);
    bpf_xdp_detach(if_index, 0, NULL);
    drop_rb_bpf__destroy(drop_rb);
    exit(0);
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
    return 0;
}

int main(int argc, char **argv)
{

    int err;
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    drop_rb = drop_rb_bpf__open_and_load();

    if (!drop_rb)
    {
        fprintf(stderr, "Failed to open and load BPF object\n");
        return 1;
    }

    if_index = if_nametoindex(argv[1]);
    if (!if_index)
    {
        fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
        return 1;
    }
    err = bpf_xdp_attach(if_index, bpf_program__fd(drop_rb->progs.drop_rb), 0, NULL);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }
    printf("BPF program attached\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // RING BUFFER
    int map_fd = bpf_map__fd(drop_rb->maps.ring_out);

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    while (1)
    {
        ring_buffer__consume(rb); // no check errors
    }

    return 0;
}
