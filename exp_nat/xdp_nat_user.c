#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "nat_structs.h"
#include "xdp_nat.skel.h"

#define PRIV_SUBNET 0xc0a80102;
#define PUB_SUBNET 0x0a000002;
#define TCP_PROTO 6
#define UDP_PROTO 17

struct xdp_nat *skel;
int ifindex = -1;

/*
    populate the nat_binding_table with the default values
*/
static int load_config()
{
    srand(42);
    struct flow_key key;
    struct binding_definition value;
    int err;
    int count_err = 0;
    // generate the default values
    for (int i = 0; i < 255; i++)
    {
        // populate the key with the fixed fields
        key.src = PUB_SUBNET + i + ((rand() % 254) << 8);
        key.dst = PUB_SUBNET + (i + 1);
        key.dst = key.dst + ((rand() % 254) << 8);
        key.port16[0] = rand() % 65535;
        key.port16[1] = rand() % 65535;
        key.proto = UDP_PROTO; //(i % 2) ? TCP_PROTO : UDP_PROTO;

        // populate the value with the fixed fields
        value.addr = PRIV_SUBNET + i;
        value.addr = value.addr + ((rand() % 254) << 8);
        value.port = rand() % 65535;

        if (i % 10)
        {
            unsigned char bytes[4];
            bytes[0] = key.dst & 0xFF;
            bytes[1] = (key.dst >> 8) & 0xFF;
            bytes[2] = (key.dst >> 16) & 0xFF;
            bytes[3] = (key.dst >> 24) & 0xFF;
            printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
            printf("key.dst: %d\n", key.dst);
            printf("key.port16[0]: %d\n", key.port16[0]);
            printf("key.port16[1]: %d\n", key.port16[1]);
            printf("key.proto: %d\n", key.proto);
            printf("value.addr: %d\n", value.addr);
            printf("value.port: %d\n", value.port);
            printf("\n");
        }

        // insert the key-value pair in the map
        /*   err = bpf_map_update_elem(bpf_map__fd(skel->maps.nat_binding_table), &key, &value, 0);
          if (err)
          {
              fprintf(stderr, "ERR: bpf_map_update_elem failed\n");
              if (count_err++ > 50)
                  return -1;
          } */
    }

    return 0;
}

static void exit_(int sig)
{
    int err;

    /*     err = bpf_xdp_detach(ifindex, 0, 0);
        if (err)
        {
            fprintf(stderr, "ERR: detach from %d\n", ifindex);
            exit(1);
        }
        if (skel)
            xdp_nat__destroy(skel);
        exit(0); */
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    /*   ifindex = if_nametoindex(argv[1]);
      if (!ifindex)
      {
          fprintf(stderr, "ERR: if_nametoindex(%s) failed\n", argv[1]);
          return 1;
      }
   */
    /*     skel = xdp_nat__open();
        if (!skel)
        {
            fprintf(stderr, "ERR: xdp_nat__open failed\n");
            return 1;
        } */
    /*
        int err = xdp_nat__load(skel);
        if (err)
        {
            fprintf(stderr, "ERR: xdp_nat__load failed\n");
            return 1;
        } */

    if (load_config())
    {
        fprintf(stderr, "ERR: load_config failed\n");
        return 1;
    }
    /*
        err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.nat_ingress), 0, 0);
        if (err)
        {
            fprintf(stderr, "ERR: bpf_xdp_attach failed\n");
            return 1;
        } */

    signal(SIGINT, exit_);
    signal(SIGTERM, exit_);

    for (;;)
        pause();

    return 0;
}