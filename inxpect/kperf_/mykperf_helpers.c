#include <asm/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include "mykperf_helpers.h"
#include "mykperf_ioctl.h"
#include "mykperf_module.h"

static inline __u64 ptr_to_u64(const void *ptr) {
  return (__u64)(unsigned long)ptr;
}

/*
 * Find the bss map in the bpf map list and return the file descriptor.
 * @return the file descriptor of the bss map, error otherwise
 */
int get_bss_map_fd(int prog_fd) {

  int fd = -1;

  struct bpf_prog_info info = {0};
  __u32 len = sizeof(info);

  int err = -1;
  // needed to know the number of maps
  if (bpf_prog_get_info_by_fd(prog_fd, &info, &len)) {
    return err;
  }

  // TODO : IMPROVE THIS

  int num_maps = info.nr_map_ids;
  __u32 map_ids[num_maps];

  struct bpf_prog_info info2 = {0};
  __u32 len2 = sizeof(info2);

  info2.nr_map_ids = num_maps;
  info2.map_ids = ptr_to_u64(map_ids);

  if (bpf_prog_get_info_by_fd(prog_fd, &info2, &len2)) {
    return err;
  }

  struct bpf_map_info info_map = {};
  len = sizeof(info_map);

  for (unsigned int i = 0; i < num_maps; i++) {
    fd = bpf_map_get_fd_by_id(map_ids[i]);
    if (fd < 0) {
      return err;
    }

    err = bpf_map_get_info_by_fd(fd, &info_map, &len);
    if (err) {
      return err;
    }

    if (strcmp(BSS_MAP,
               info_map.name + strlen(info_map.name) - strlen(BSS_MAP)) == 0) {
      break;
    }
    close(fd);
  }
  // fprintf(stdout, "Map name: %s\n", info_map.name);
  return fd;
}

int get_rodata_map_fd(int prog_fd) {
  int err = -1;

  int fd = -1;

  struct bpf_prog_info info = {0};
  __u32 len = sizeof(info);
  // needed to know the number of maps
  if (bpf_prog_get_info_by_fd(prog_fd, &info, &len)) {
    return err;
  }

  // TODO : IMPROVE THIS

  int num_maps = info.nr_map_ids;
  __u32 map_ids[num_maps];

  struct bpf_prog_info info2 = {0};
  len = sizeof(info2);

  info2.nr_map_ids = num_maps; // needed otherwise map_ids is not filled
  info2.map_ids = ptr_to_u64(map_ids);
  // retrieve the map ids
  if (bpf_prog_get_info_by_fd(prog_fd, &info2, &len)) {
    return err;
  }

  struct bpf_map_info info_map = {};
  len = sizeof(info_map);

  for (unsigned int i = 0; i < num_maps; i++) {
    fd = bpf_map_get_fd_by_id(map_ids[i]);
    if (fd < 0) {
      return err;
    }

    err = bpf_map_get_info_by_fd(fd, &info_map, &len);
    if (err) {
      return err;
    }

    if (strcmp(RODATA_MAP, info_map.name + strlen(info_map.name) -
                               strlen(RODATA_MAP)) == 0) {
      break;
    }
    close(fd);
  }
  // fprintf(stdout, "Map name: %s\n", info_map.name);
  return fd;
}

int get_data_map_fd(int prog_fd) {
  int err = -1;

  int fd = -1;

  struct bpf_prog_info info = {0};
  __u32 len = sizeof(info);
  // needed to know the number of maps
  if (bpf_prog_get_info_by_fd(prog_fd, &info, &len)) {
    return err;
  }

  // TODO : IMPROVE THIS

  int num_maps = info.nr_map_ids;
  __u32 map_ids[num_maps];

  struct bpf_prog_info info2 = {0};
  len = sizeof(info2);

  info2.nr_map_ids = num_maps; // needed otherwise map_ids is not filled
  info2.map_ids = ptr_to_u64(map_ids);
  // retrieve the map ids
  if (bpf_prog_get_info_by_fd(prog_fd, &info2, &len)) {
    return err;
  }

  struct bpf_map_info info_map = {};
  len = sizeof(info_map);

  for (unsigned int i = 0; i < num_maps; i++) {
    fd = bpf_map_get_fd_by_id(map_ids[i]);
    if (fd < 0) {
      return err;
    }

    err = bpf_map_get_info_by_fd(fd, &info_map, &len);
    if (err) {
      return err;
    }
    if (strcmp(DATA_MAP,
               info_map.name + strlen(info_map.name) - strlen(DATA_MAP)) == 0) {

      break;
    }
    close(fd);
    fd = -1;
  }
  // fprintf(stdout, "Map name: %s\n", info_map.name);
  return fd;
}
/*
 * Set the shared variable beetwen usersapce and xdp to `out_reg` value, so xdp
 * knows where read the counter value.
 * @param out_reg: the value to set
 * @param funcname: the name of the xdp function
 * @return 0 if the operation is successful, -1 otherwise
 */
/* int set_counter(__u64 out_reg)
{
    __u32 zero = 0;
    int fd = -1;
    int err;

    fd = get_bss_map_fd();
    if (fd < 0)
    {
        fprintf(stderr, "Failed to find data map\n");
        return -1;
    }

    struct bss data = {0};

    err = bpf_map_lookup_elem(fd, &zero, &data);
    if (err)
    {
        fprintf(stderr, "Failed to update map element\n");
        return -1;
    }

    data.reg_counter = out_reg;

    err = bpf_map_update_elem(fd, &zero, &data, 0);
    if (err)
    {
        fprintf(stderr, "Failed to update map element\n");
        return -1;
    }

    close(fd);
    return 0;
} */

/*
 * Enable the passed event and write the result in the out_reg.
 * `out_reg` is the register where measurments are stored
 * @param event: the event to enable
 * @param out_reg: the register where to write the result
 * @return 0 if the operation is successful, -1 otherwise
 */
int enable_event(__u64 event, int *out_reg, int cpu) {
  int fd;
  fd = open(DEVICE_FILE, O_RDWR);
  if (fd < 0) {
    perror("Failed to open the device");
    return -1;
  }

  fprintf(stdout, "Enabling event %llx\n", event);

  struct message msg = {
      .event = event,
      .cpu = cpu,
  };

  if (ioctl(fd, ENABLE_EVENT, &msg) < 0) {
    perror("Failed to perform IOCTL GET");
    close(fd);
    return -1;
  }

  *out_reg = msg.reg;

  /*     if (set_counter(*out_reg) < 0)
      {
          perror("Failed to set counter in xdp program");
          close(fd);
          return -1;
      } */

  close(fd);
  return 0;
}

/*
 * Disable the passed event.
 * @param event: the event to disable
 * @return 0 if the operation is successful, -1 otherwise
 */
int disable_event(__u64 event, __u64 reg, int cpu) {
  struct message msg = {
      .event = event,
      .reg = reg,
      .cpu = cpu,
  };

  fprintf(stdout, "Disabling event %llx on cpu %d from reg: %llx\n", event, cpu,
          reg);

  int fd;
  fd = open(DEVICE_FILE, O_RDWR);
  if (fd < 0) {
    perror("Failed to open the device.");
    return -1;
  }

  if (ioctl(fd, DISABLE_EVENT, &msg) < 0) {
    perror("Failed to perform IOCTL GET");
    close(fd);
    return -1;
  }

  close(fd);
  return 0;
}