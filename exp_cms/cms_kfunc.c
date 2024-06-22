#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include "cms_kfunc.skel.h"
#include "cms.h"


int if_index;
struct cms_kfunc_bpf* cms_kfunc;

int handler(void *ctx, void *data, size_t len) {
	return 0;
}
void sig_handler(int sig) {
	// compute the CMS load factor
	//int key = 0;
	//struct cms cms_struct;
	//bpf_map__lookup_elem(cms_kfunc->maps.cms_map, &key, sizeof(key), &cms_struct, sizeof(cms_struct), 0);
	//cms_kfunc->maps.cms_map;
	
	struct cms cms_map;
	__u32 key = 0;
	__u32 usage = 0;
	__u32 count = 0;

	int map_fd = bpf_map__fd(cms_kfunc->maps.cms_map);
	if (map_fd < 0) {
		printf("Failed to get map fd: %s\n", strerror(errno));
		exit(1);
	}

	if(bpf_map_lookup_elem(map_fd, &key, &cms_map)){
		printf("Failed to lookup element: %s\n", strerror(errno));
		exit(1);
	}
	for (uint32_t j = 0; j < CMS_ROWS; j++) 
		for (uint32_t i = 0; i < CMS_SIZE; i++)
			if (cms_map.count[j][i] != 0) 
				count++;

	printf("load factor: %lf\n", ((double)count)/(CMS_ROWS*CMS_SIZE));

	bpf_xdp_detach(if_index, 0, NULL);
	cms_kfunc_bpf__destroy(cms_kfunc);
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
}
int main(int argc, char **argv) {

	int err;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}

	bump_memlock_rlimit();

	cms_kfunc = cms_kfunc_bpf__open_and_load();

	if (!cms_kfunc) {
		fprintf(stderr, "Failed to open and load BPF object\n");
		return 1;
	}

	if_index = if_nametoindex(argv[1]);

	err = bpf_xdp_attach(if_index, bpf_program__fd(cms_kfunc->progs.cms_kfunc), 0, NULL);

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

