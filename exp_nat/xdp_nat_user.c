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

    for (int i = 0; i < 255; i += 2)
    {
        int second_field = rand() % 254;
        key.src = (second_field << 8) | PUB_SUBNET;
        key.src |= i;

        // populate the key with the fixed fields
        key.dst = (((second_field + (rand() % 127) % 254) + 1) << 8) | PUB_SUBNET;
        key.dst |= (i + 1);
        key.port16[0] = rand() % 65535;
        key.port16[1] = rand() % 65535;
        key.proto = UDP_PROTO; //(i % 2) ? TCP_PROTO : UDP_PROTO;

        // populate the value with the fixed fields
        value.addr = value.addr + ((rand() % 254) << 8) | PRIV_SUBNET;
        value.addr |= i;
        value.port = rand() % 65535;

        // print dst and src ips

        printf("src: %d.%d.%d.%d\n", key.src & 0xff, (key.src >> 8) & 0xff, (key.src >> 16) & 0xff,
               (key.src >> 24) & 0xff);

        printf("dst: %d.%d.%d.%d\n", key.dst & 0xff, (key.dst >> 8) & 0xff, (key.dst >> 16) & 0xff,
               (key.dst >> 24) & 0xff);

        // check if there are dst and src with the same 2 fields
        if ((key.src & 0x0000ff00) == (key.dst & 0x0000ff00))
        {
            printf("ERR: src and dst have the same 2 fields\n");
            return -1;
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

    /*   for (;;)
          sleep(); */

    return 0;
}