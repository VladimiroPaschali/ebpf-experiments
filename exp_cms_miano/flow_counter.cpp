#include <iostream>
#include <unordered_set>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define ETHERTYPE_IP 0x0800
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

using namespace std;

struct FlowKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const FlowKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port;
    }
};

namespace std {
    template <>
    struct hash<FlowKey> {
        size_t operator()(const FlowKey& key) const {
            size_t hash = 17;
            hash = hash * 31 + key.src_ip;
            hash = hash * 31 + key.dst_ip;
            hash = hash * 31 + key.src_port;
            hash = hash * 31 + key.dst_port;
            return hash;
        }
    };
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <pcap_file>" << endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        cerr << "Error opening pcap file: " << errbuf << endl;
        return 1;
    }

    unordered_set<FlowKey> flows;
    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Extracting Ethernet header
        struct ethhdr *eth = (struct ethhdr *)(packet);

        // Check if packet is IP
        if (ntohs(eth->h_proto) != ETHERTYPE_IP) {
            continue;
        }

        // Extracting IP header
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));

        // Check if packet is TCP
        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
            continue;
        }

	if (ip->protocol == IPPROTO_TCP) {
        // Extracting TCP header
        	struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

        	// Create flow key
        	FlowKey key = {ip->saddr, ip->daddr, ntohs(tcp->source), ntohs(tcp->dest)};
        	flows.insert(key);
	}

	if (ip->protocol == IPPROTO_UDP) {
        // Extracting TCP header
        	struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

        	// Create flow key
        	FlowKey key = {ip->saddr, ip->daddr, ntohs(udp->source), ntohs(udp->dest)};
        	flows.insert(key);
	}

    }

    cout << "Number of TCP flows: " << flows.size() << endl;

    pcap_close(handle);
    return 0;
}

