#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "fexit.skel.h"


int main(int argc, char* argv[]) {
	int fd = atoi(argv[1]);
	struct fexit_bpf* skel = fexit_bpf__open();
	int dst_prog = bpf_prog_get_fd_by_id(fd);
	if (dst_prog < 0) {
		perror("Unable to open dst prog\n");
		return -1;
	}
	struct bpf_program* program;
	bpf_object__for_each_program(program, skel->obj) {
		if (bpf_program__set_attach_target(program, dst_prog, argv[2] ) < 0 ) {
			perror("Unable to set attach tgt to dst prog\n");
			return -1;
		}
	}
	if ( fexit_bpf__load(skel) < 0 ) {
		perror("Unable to load prog\n");
		return -1;
	}
	if ( fexit_bpf__attach(skel) < 0 ) {
		perror("Unable to attach prog\n");
		return -1;
	}
	while(1); 
}

