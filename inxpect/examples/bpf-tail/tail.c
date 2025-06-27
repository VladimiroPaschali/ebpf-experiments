#include "tail.bpf.skel.h"

#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>

int if_index;
struct tail_bpf *tail;


void sig_handler(int sig) {
  bpf_xdp_detach(if_index, 0, NULL);
  tail_bpf__destroy(tail);
  exit(0);
}

void bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

int fill_tail_tbl(int *prog_fds) {
  for (int i = 0; i < 3; i++) {
    int err = bpf_map__update_elem(tail->maps.map_tail, &i, sizeof(int),
                                   &prog_fds[i], sizeof(int), 0);
    if (err) {
      printf("Failed to update tail table, err %d\n", err);
      return -1;
    }
  }

  return 0;
}

int main(int argc, char **argv) {

  int err;
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
    return 1;
  }

  bump_memlock_rlimit();

  tail = tail_bpf__open_and_load();
  if (!tail) {
    fprintf(stderr, "Failed to open and load BPF object\n");
    return 1;
  }

  if_index = if_nametoindex(argv[1]);
  if (!if_index) {
    fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
    return 1;
  }

  int prog_fds[3] = {bpf_program__fd(tail->progs.tail),
                     bpf_program__fd(tail->progs.prog1),
                     bpf_program__fd(tail->progs.prog2)};

  if (fill_tail_tbl(prog_fds) < 0) {
    fprintf(stderr, "Failed to fill tail table\n");
    return 1;
  }

  err = bpf_xdp_attach(if_index, bpf_program__fd(tail->progs.tail), 0, NULL);
  if (err) {
    fprintf(stderr, "Failed to attach BPF program\n");
    return 1;
  }
  printf("BPF program attached\n");

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  while (1)
    ;

  return 0;
}
