#!/bin/env python3
import argparse
import random

from scapy.all import  Raw, wrpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.volatile import *


INIT_PRIVATE_IP = 0xC0A80001
END_PRIVATE_IP = 0xC0A800FF
INIT_PUBLIC_IP = 0x0A000001
END_PUBLIC_IP = 0x0A00FFFF


def ip_from_int_to_str(ip):
    return ".".join(map(str, [ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF]))

def generate_flow():
    return (random.randint(INIT_PRIVATE_IP, END_PRIVATE_IP),
            random.randint(INIT_PUBLIC_IP, END_PUBLIC_IP),
            random.randint(1024, 65535),
            random.randint(1024, 65535))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate a pcap file with random packets')
    parser.add_argument('output', help='Output file')
    parser.add_argument('packet_count', type=int, help='Number of packets to generate')
    parser.add_argument('flow_count', type=int, help='Number of flows to generate')
    args = parser.parse_args()

    #init flow list
    flow_set = set()
    while len(flow_set) < args.flow_count:
        flow_set.add(generate_flow())
    flow_list = list(flow_set)
    used_flows = [0] * len(flow_list)
    print(len(flow_list))
    print(len(used_flows))
    for i in range(args.packet_count):
        flow_index = random.randint(0, len(flow_list) - 1)
        print(flow_index)
        print(flow_list[flow_index])
        pkt = None
        if (used_flows[flow_index] == 0):
            # generate packet from private to public ip
            pkt = IP(src=ip_from_int_to_str(flow_list[flow_index][0]), dst=ip_from_int_to_str(flow_list[flow_index][1])) / TCP(sport=flow_list[flow_index][2], dport=flow_list[flow_index][3]) / Raw(load="A" * 100)
            used_flows[flow_index] = 1
        else:
            # generate packet from public to private ip or vice versa
            if (random.randint(0, 1) == 0):
                pkt = IP(src=ip_from_int_to_str(flow_list[flow_index][1]), dst=ip_from_int_to_str(flow_list[flow_index][0])) / TCP(sport=flow_list[flow_index][3], dport=flow_list[flow_index][2]) / Raw(load="A" * 100)
            else:
                pkt = IP(src=ip_from_int_to_str(flow_list[flow_index][0]), dst=ip_from_int_to_str(flow_list[flow_index][1])) / TCP(sport=flow_list[flow_index][2], dport=flow_list[flow_index][3]) / Raw(load="A" * 100)
        pkt.show()
        wrpcap(args.output, pkt, append=True)

