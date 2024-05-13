#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include "cms.skel.h"
#include "cms.h"


int if_index;
struct cms_bpf* cms;

void sig_handler(int sig) {

	struct cms cms_map;
	__u32 key = 0;
	__u32 usage = 0;

	int map_fd = bpf_map__fd(cms->maps.cms_map);
	if (map_fd < 0) {
		printf("Failed to get map fd: %s\n", strerror(errno));
		exit(1);
	}

	if(bpf_map_lookup_elem(map_fd, &key, &cms_map)){
		printf("Failed to lookup element: %s\n", strerror(errno));
		exit(1);
	}

	printf("CMS map:\n");

	// printf("sizeof cms_map: %lu\n", sizeof(cms_map));
	for (__u32 i = 0; i < CMS_SIZE; i++) {
		if (cms_map.count[0][i] != 0) {
			usage++;
			// printf("Row %d, index %d, count %d\n", 0, i, cms_map.count[0][i]);
		}
	}

	printf("Usage: %f%% \n", ((float)usage/CMS_SIZE)*100);
	bpf_xdp_detach(if_index, 0, NULL);
	cms_bpf__destroy(cms);
	exit(0);
}

void bump_memlock_rlimit(void) {
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_STACK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_STACK limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_DATA, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_DATA limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_AS, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_AS limit!\n");
		exit(1);
	}
}
int main(int argc, char **argv) {

	int err;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}

	bump_memlock_rlimit();

	cms = cms_bpf__open_and_load();

	if (!cms) {
		fprintf(stderr, "Failed to open and load BPF object\n");
		return 1;
	}

	if_index = if_nametoindex(argv[1]);
	if (!if_index) {
		fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
		return 1;
	}
	err = bpf_xdp_attach(if_index, bpf_program__fd(cms->progs.cms), 0, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		return 1;
	}
	printf("BPF program attached\n");


	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while(1);

	return 0;
}

