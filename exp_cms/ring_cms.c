#include <bpf/libbpf.h>
#include "cms.h"
#include "ring_cms.skel.h"
#include <signal.h>
#include <sys/resource.h>
#include <net/if.h>



int if_index; 
struct ring_cms_bpf* cms;
struct ring_buffer *rb;
struct cms cms_struct;

static volatile bool exiting = false;

static void sig_handler(int sig)
{

	bpf_xdp_detach(if_index, 0, NULL);
	ring_buffer__free(rb);
	ring_cms_bpf__destroy(cms);
	exit(0);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int handle_event(void *ctx, void *data, size_t data_sz)
{

	const struct event *e = data;

	//printf("hash = %d",e->hash);
	//printf("row_index = %d\n",e->row_index);
	//printf("hash = %d\n",e->hash);
	//printf("old value = %u\n",cms_struct.count[e->row_index][e->hash]);
	for (int i = 0; i < CMS_ROWS; i++) {
		cms_struct.count[i][((((e->hash)>>16*i) & 0xFFFF)%CMS_SIZE)]++;
	}
	//printf("new value = %u\n",cms_struct.count[e->row_index][e->hash]);

	return 0;
}

int main( int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}
	cms = ring_cms_bpf__open_and_load();
	rb = NULL;
	int err;

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	if (!cms) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint */
	//err = ring_cms_bpf__attach(cms);
	//if (err) {
	//	fprintf(stderr, "Failed to attach BPF skeleton\n");
	//	goto cleanup;
	//}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(cms->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	printf("ao\n");

	// int errore = ring_buffer__consume(rb);
	// if (errore<0) {
	// 	err = -1;
	// 	fprintf(stderr, "Failed to consume\n");
	// 	goto cleanup;
	// }
	//
	// attach the bpf program
	if_index = if_nametoindex(argv[1]);

	err = bpf_xdp_attach(if_index,  bpf_program__fd(cms->progs.ring_cms), 0, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
		// printf("polling\n");

	}


	cleanup:
		ring_buffer__free(rb);
		bpf_xdp_detach(if_index, 0, NULL);
		ring_cms_bpf__destroy(cms);
		return err < 0 ? -err : 0;
}

