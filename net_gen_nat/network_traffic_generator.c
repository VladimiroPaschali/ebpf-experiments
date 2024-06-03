#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <signal.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_jhash.h>


#define TABLE_SIZE 16384
#define noop ((void)0)
#define DEBUG 0
#define DEBUG_PRINT(fmt, args...) \
if (DEBUG) \
	   printf(fmt, ##args); 

#define DEBUG_PRINT_PKT(pkt) \
if (DEBUG) { \
	   printf("Packet: "); \
	   for (int i = 0; i < pkt->data_len; i++) { \
		   printf("%02x ", pkt->buf_addr[i]); \
	   } \
	   printf("\n"); \
}

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define INTERNAL_IP_START 0xc0a80001
#define INTERNAL_IP_END 0xc0a800fe
#define PUBLIC_IP_START 0x0a000001
#define PUBLIC_IP_END 0x0a0000fe
#define NAT_IP  0x0b000001
#define INTERNAL_PORT_START 1024
#define INTERNAL_PORT_END 65535
#define PUBLIC_PORT_START 1024
#define PUBLIC_PORT_END 65535

struct rte_mempool *mbuf_pool;
/* Flow table entry */
struct flow_entry {
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint64_t last_used;
};

/* Flow table */
struct flow_table {
	struct flow_entry *entries;
	uint32_t size;
	uint32_t capacity;
} flow_table;

/* NAT table entry */
struct nat_entry {
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dst_ip;
	uint16_t dst_port;
};

static const struct rte_hash_parameters hash_params = {
	.name = "nat_hash_table",
	.entries = TABLE_SIZE,
	.key_len = sizeof(struct nat_entry),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.socket_id = 0,
};

struct rte_hash *nat_hash_table;
struct nat_entry entries[TABLE_SIZE];
int inserted_nat_entries = 0;
int total_tx_pkts = 0;


static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_lro_pkt_size = RTE_ETHER_MAX_LEN }
};

static void signal_handler(int signum) {
		rte_free(flow_table.entries);
		//rte_free(nat_table.entries);
		/* free mbuff pool */
		rte_mempool_free(mbuf_pool);
		exit(0);
}

static void generate_flows() {
	/* generate random flows */
	uint32_t i;
	for (i = 0; i < flow_table.capacity; i++) {
		flow_table.entries[i].src_ip = (INTERNAL_IP_START + rand() % (INTERNAL_IP_END - INTERNAL_IP_START + 1));
		flow_table.entries[i].src_port = (INTERNAL_PORT_START + (rand() % (INTERNAL_PORT_END - INTERNAL_PORT_START + 1)));
		flow_table.entries[i].dst_ip = (PUBLIC_IP_START + rand() % (PUBLIC_IP_END - PUBLIC_IP_START + 1));
		flow_table.entries[i].dst_port = (PUBLIC_PORT_START + (rand() % (PUBLIC_PORT_END - PUBLIC_PORT_START + 1)));
		flow_table.size++;
	}
}
static void
initialize_port(uint16_t port_id, struct rte_mempool *mbuf_pool) {
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = 16;
	uint16_t nb_txd = 16;
	int retval;
	uint16_t q;

	if (port_id >= rte_eth_dev_count_avail()) {
		rte_exit(EXIT_FAILURE, "Port %u is not available\n", port_id);
	}

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
	if (retval != 0) {
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", retval, port_id);
	}

	/* print port name */
	char port_name[32];
	retval = rte_eth_dev_get_name_by_port(port_id, port_name);
	printf("Port %u name: %s\n", port_id, port_name);

	/* Allocate and set up RX queues. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
				rte_eth_dev_socket_id(port_id), NULL, mbuf_pool);
		if (retval < 0) {
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%u\n", retval, port_id);
		}
	}

	/* Allocate and set up TX queues. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port_id, q, nb_txd,
				rte_eth_dev_socket_id(port_id), NULL);
		if (retval < 0) {
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%u\n", retval, port_id);
		}
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port_id);
	if (retval < 0) {
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%u\n", retval, port_id);
	}

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	rte_eth_macaddr_get(port_id, &addr);
	printf("Port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			port_id,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port_id);
	DEBUG_PRINT("Port %u initialized\n", port_id);
}

static void
generate_traffic(uint16_t port_id, struct rte_mempool *mbuf_pool) {
	struct rte_mbuf *mbufs[BURST_SIZE];
	uint16_t nb_tx;
	uint16_t nb_rx;
	int i;

	while (1) {
		/* Receive packets */
		nb_rx = rte_eth_rx_burst(port_id, 0, mbufs, BURST_SIZE);
		if (unlikely(nb_rx == 0))
			noop;
		else {
			/* Parse received packets */
			for (i = 0; i < nb_rx; i++) {
				DEBUG_PRINT("Parsing packet %d\n", i);
				struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
				/* parse if IP packet */
				if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
					struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
					/* parse if TCP packet */
					if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
						struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
						/* add entry to NAT table */
						struct nat_entry temp;
						/* save the mapping */
						temp.src_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
						temp.src_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
						temp.dst_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
						temp.dst_port = rte_be_to_cpu_16(tcp_hdr->src_port);
						/* print the mapping formatting source and destination ip */
						char src_ip[16];
						char dst_ip[16];
						sprintf(src_ip, "%d.%d.%d.%d", (temp.src_ip >> 24) & 0xff, (temp.src_ip >> 16) & 0xff, (temp.src_ip >> 8) & 0xff, temp.src_ip & 0xff);
						sprintf(dst_ip, "%d.%d.%d.%d", (temp.dst_ip >> 24) & 0xff, (temp.dst_ip >> 16) & 0xff, (temp.dst_ip >> 8) & 0xff, temp.dst_ip & 0xff);
						//printf("Received packet: %s -> %s\n", src_ip, dst_ip);
						// map only if  the src ip (that now is in dest) is the nat
						if (temp.dst_ip != NAT_IP)
							goto free_buf;
						if (rte_hash_lookup(nat_hash_table, &temp) >= 0) {
							// found
							//printf("entry found\n");
						} else {
							// else update map
							//printf("entry not found\n");
							if (inserted_nat_entries < TABLE_SIZE) {
								if (rte_hash_add_key_data(nat_hash_table, &temp, 0) < 0 ) {
									printf("not able to insert key\n");
									exit(-1);
								}
								entries[inserted_nat_entries] = temp;
								inserted_nat_entries++;
								/* print the mapping formatting source and destination ip */
								char src_ip[16];
								char dst_ip[16];
								sprintf(src_ip, "%d.%d.%d.%d", (entries[inserted_nat_entries- 1].src_ip >> 24) & 0xff, (entries[inserted_nat_entries - 1].src_ip >> 16) & 0xff, (entries[inserted_nat_entries - 1].src_ip >> 8) & 0xff, entries[inserted_nat_entries - 1].src_ip & 0xff);
								sprintf(dst_ip, "%d.%d.%d.%d", (entries[inserted_nat_entries - 1].dst_ip >> 24) & 0xff, (entries[inserted_nat_entries - 1].dst_ip >> 16) & 0xff, (entries[inserted_nat_entries - 1].dst_ip >> 8) & 0xff, entries[inserted_nat_entries - 1].dst_ip & 0xff);
								//printf("NAT Table Entry: %s:%d -> %s:%d\n", src_ip, entries[inserted_nat_entries - 1].src_port, dst_ip, entries[inserted_nat_entries - 1].dst_port);
							}

						}

					}
				}
				/* free the packet */
free_buf:
				rte_pktmbuf_free(mbufs[i]);
			}
		}
		/* Allocate packets from the memory pool. */
		//if (total_tx_pkts < MAX_PACKETS) {
			for (i = 0; i < BURST_SIZE; i++) {
				DEBUG_PRINT("Allocating tx packet %d\n", i);
				mbufs[i] = rte_pktmbuf_alloc(mbuf_pool);
				if (mbufs[i] == NULL) {
					rte_exit(EXIT_FAILURE, "Failed to allocate mbuf\n");
				}
				DEBUG_PRINT("Allocated tx packet %d\n", i);

				/* Initialize the packet data (simple example with zeroed payload). */
				struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
				memset(eth_hdr, 0, sizeof(struct rte_ether_hdr));
				

				if (inserted_nat_entries == 0 || rand() % 2 == 0) {
				//if (1) {
					/* randomly select a packet from one of the flows */
					DEBUG_PRINT("Selecting packet from flow table\n");
					DEBUG_PRINT("Flow table size: %u\n", flow_table.size);
					struct flow_entry flow = flow_table.entries[rand() % flow_table.size];
					eth_hdr->dst_addr.addr_bytes[0] = 0x00;
					eth_hdr->dst_addr.addr_bytes[1] = 0x00;
					eth_hdr->dst_addr.addr_bytes[2] = 0x00;
					eth_hdr->dst_addr.addr_bytes[3] = 0x00;
					eth_hdr->dst_addr.addr_bytes[4] = 0x00;
					eth_hdr->dst_addr.addr_bytes[5] = 0x00;
					eth_hdr->src_addr.addr_bytes[0] = 0x00;
					eth_hdr->src_addr.addr_bytes[1] = 0x00;
					eth_hdr->src_addr.addr_bytes[2] = 0x00;
					eth_hdr->src_addr.addr_bytes[3] = 0x00;
					eth_hdr->src_addr.addr_bytes[4] = 0x00;
					eth_hdr->src_addr.addr_bytes[5] = 0x00;
					eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

					struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
					ipv4_hdr->version_ihl = 0x45;
					ipv4_hdr->type_of_service = 0;
					ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
					ipv4_hdr->packet_id = 0;
					ipv4_hdr->fragment_offset = 0;
					ipv4_hdr->time_to_live = 64;
					ipv4_hdr->next_proto_id = IPPROTO_TCP;
					ipv4_hdr->hdr_checksum = 0;
					ipv4_hdr->src_addr = rte_cpu_to_be_32(flow.src_ip);
					ipv4_hdr->dst_addr = rte_cpu_to_be_32(flow.dst_ip);

					struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
					tcp_hdr->src_port = rte_cpu_to_be_16(flow.src_port);
					tcp_hdr->dst_port = rte_cpu_to_be_16(flow.dst_port);
					tcp_hdr->sent_seq = 0;
					tcp_hdr->recv_ack = 0;
					tcp_hdr->data_off = 0x50;
					tcp_hdr->tcp_flags = 0x02;
					tcp_hdr->rx_win = 0;
					tcp_hdr->cksum = 0;
					tcp_hdr->tcp_urp = 0;
				} else {
					/* randomly select a packet from NAT table */
					DEBUG_PRINT("Selecting packet from NAT table\n");
					DEBUG_PRINT("NAT table size: %u\n", inserted_nat_entries);
					struct nat_entry nat = entries[rand() % inserted_nat_entries];
					eth_hdr->dst_addr.addr_bytes[0] = 0x00;
					eth_hdr->dst_addr.addr_bytes[1] = 0x00;
					eth_hdr->dst_addr.addr_bytes[2] = 0x00;
					eth_hdr->dst_addr.addr_bytes[3] = 0x00;
					eth_hdr->dst_addr.addr_bytes[4] = 0x00;
					eth_hdr->dst_addr.addr_bytes[5] = 0x00;
					eth_hdr->src_addr.addr_bytes[0] = 0x00;
					eth_hdr->src_addr.addr_bytes[1] = 0x00;
					eth_hdr->src_addr.addr_bytes[2] = 0x00;
					eth_hdr->src_addr.addr_bytes[3] = 0x00;
					eth_hdr->src_addr.addr_bytes[4] = 0x00;
					eth_hdr->src_addr.addr_bytes[5] = 0x00;
					eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
					
					struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
					ipv4_hdr->version_ihl = 0x45;
					ipv4_hdr->type_of_service = 0;
					ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr));
					ipv4_hdr->packet_id = 0;
					ipv4_hdr->fragment_offset = 0;
					ipv4_hdr->time_to_live = 64;
					ipv4_hdr->next_proto_id = IPPROTO_TCP;
					ipv4_hdr->hdr_checksum = 0;
					ipv4_hdr->src_addr = rte_cpu_to_be_32(nat.src_ip);
					ipv4_hdr->dst_addr = rte_cpu_to_be_32(nat.dst_ip);

					struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
					tcp_hdr->src_port = rte_cpu_to_be_16(nat.src_port);
					tcp_hdr->dst_port = rte_cpu_to_be_16(nat.dst_port);
					tcp_hdr->sent_seq = 0;
					tcp_hdr->recv_ack = 0;
					tcp_hdr->data_off = 0x50;
					tcp_hdr->tcp_flags = 0x02;
					tcp_hdr->rx_win = 0;
					tcp_hdr->cksum = 0;
					tcp_hdr->tcp_urp = 0;

					/* update last used timestamp */
				}

				/* Set the packet length. */
				//mbufs[i]->data_len = sizeof(struct rte_ether_hdr);
				//mbufs[i]->pkt_len = sizeof(struct rte_ether_hdr);
				mbufs[i]->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
				mbufs[i]->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
			}
		///* Transmit the burst of packets on an output interface. */
		nb_tx = rte_eth_tx_burst(port_id, 0, mbufs, BURST_SIZE);
		total_tx_pkts += nb_tx;
		DEBUG_PRINT("Transmitted %d packets\n", nb_tx);
		//if (unlikely(nb_tx < BURST_SIZE)) {
			for (i = nb_tx; i < BURST_SIZE; i++) {
				rte_pktmbuf_free(mbufs[i]);
			}
		//}
		}

	//}
}

int
main(int argc, char *argv[]) {
	unsigned nb_ports;
	uint16_t port_id;

	/* Initialize the Environment Abstraction Layer (EAL). */
	/* return number of parser args */
	DEBUG_PRINT("before eal init\n");
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	}
	DEBUG_PRINT("after eal init\n");
	argc -= ret;
	argv += ret;

	DEBUG_PRINT("before eth dev count\n");
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
	}
	DEBUG_PRINT("after eth dev count\n");


	/* Create a new mempool in memory to hold the mbufs. */
	DEBUG_PRINT("before mbuf pool create\n");
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
			MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	}
	DEBUG_PRINT("after mbuf pool create\n");

	nb_ports = 1;
	/* Initialize all ports. */
	DEBUG_PRINT("before port init\n");
	for (port_id = 0; port_id < nb_ports; port_id++) {
		initialize_port(port_id, mbuf_pool);
	}
	DEBUG_PRINT("after port init\n");


	nat_hash_table = rte_hash_create(&hash_params);
	if (nat_hash_table == NULL) {
		rte_panic("Cannot create nat hash table\n");
	}

	///* Initialize flow table */
	flow_table.size = 0;
	flow_table.capacity = 1 << 4;
	flow_table.entries = rte_zmalloc("Flow Table", flow_table.capacity * sizeof(struct flow_entry), 0);
	if (flow_table.entries == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot allocate flow table\n");
	}
	DEBUG_PRINT("before generate flows\n");

	/* Generate flows */
	generate_flows();
	DEBUG_PRINT("after generate flows\n");


	/* Register signal handler */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	//while(1);
	/* Generate traffic on port 0 (for simplicity, using only the first port). */
	generate_traffic(0, mbuf_pool);

	return 0;
}

