#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>
#include "lpmtrie.skel.h"

#include <arpa/inet.h>
#include <assert.h> 

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};


int if_index;
struct lpmtrie_bpf* lpmtrie;

void sig_handler(int sig) {
	bpf_xdp_detach(if_index, 0, NULL);
	lpmtrie_bpf__destroy(lpmtrie);
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


void updatelpm() {
    __u64 counttot=0;

    struct ipv4_lpm_key key;

    for(__u8 i=1; i<=32;i++){
        __u64 count=0;
        FILE *fp;
        char string[50];
        sprintf(string,"/opt/ebpf-experiments/exp_routing/mappe/%d.txt",i);
        fp = fopen(string, "r");
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        if (fp == NULL){
            printf("Map file not found\n");
            continue;
        }
        while ((read = getline(&line, &len, fp)) != -1) {
            line[strcspn(line,"\n")]=0;
            key.prefixlen = i;
            key.data = inet_addr(line);
            assert(bpf_map__update_elem(lpmtrie->maps.lpm, &key,sizeof(struct ipv4_lpm_key), &i,sizeof(i), BPF_ANY)==0);
            count++;
            counttot++;
        }
        fclose(fp);
	    	if (line)
		free(line);
		printf("Rules in map n %d = %llu Total number of rules = %llu\n",i,count,counttot);
    }
}

int main(int argc, char **argv) {

	int err;
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}

	bump_memlock_rlimit();

	lpmtrie = lpmtrie_bpf__open_and_load();

	if (!lpmtrie) {
		fprintf(stderr, "Failed to open and load BPF object\n");
		return 1;
	}

	if_index = if_nametoindex(argv[1]);
	if (!if_index) {
		fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
		return 1;
	}
	err = bpf_xdp_attach(if_index, bpf_program__fd(lpmtrie->progs.lpmtrie), 0, NULL);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		return 1;
	}
	printf("BPF program attached\n");

    //saves the rules from the map files into the lpm map
    updatelpm();


	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while(1);

	return 0;
}

