#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include "cms_kfunc.skel.h"


int if_index;
struct cms_kfunc_bpf* cms_kfunc;

int handler(void *ctx, void *data, size_t len) {
	return 0;
}
void sig_handler(int sig) {
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

