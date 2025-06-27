#!/bin/env python3
import argparse
import random

from scapy.all import  Raw, wrpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.volatile import *


INIT_PRIVATE_IP = 0xC0A80001
END_PRIVATE_IP  = 0xC0A800FF
NAT_PUBLIC_IP   = 0x0B000001
INIT_PUBLIC_IP  = 0x0A000001
END_PUBLIC_IP   = 0x0A00FFFF

FIRST_OUTPUT_PORT = 10000

PAYLOAD_PER_PKT = 1

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

    output_port = FIRST_OUTPUT_PORT
    #init flow list
    flow_set = set()
    while len(flow_set) < args.flow_count:
        flow_set.add(generate_flow())
    flow_list = list(flow_set)
    used_flows = [0] * len(flow_list)
    private_to_public = [0] * len(flow_list)
    public_to_private = [0] * len(flow_list)
    port_list = [0] * len(flow_list)
    #print(len(flow_list))
    #print(len(used_flows))
    for i in range(args.packet_count):
        if (i % 50000 == 0):
            print("Created {} packets".format(i))
        flow_index = random.randint(0, len(flow_list) - 1)
        #print(flow_index)
        #print(flow_list[flow_index])
        pkt = None
        if (used_flows[flow_index] == 0):
            # generate packet from private to public ip
            pkt = IP(src=ip_from_int_to_str(flow_list[flow_index][0]), dst=ip_from_int_to_str(flow_list[flow_index][1])) / TCP(sport=flow_list[flow_index][2], dport=flow_list[flow_index][3], flags="S")# / Raw(load="A" * PAYLOAD_PER_PKT)
            used_flows[flow_index] = 1
            port_list[flow_index] = output_port
            output_port += 1
        elif (used_flows[flow_index] == 1):
            pkt = IP(src=ip_from_int_to_str(flow_list[flow_index][1]), dst=ip_from_int_to_str(NAT_PUBLIC_IP)) / TCP(sport=flow_list[flow_index][3], dport=port_list[flow_index], flags="SA")# / Raw(load="A" * PAYLOAD_PER_PKT)
            used_flows[flow_index] = 2
        else:
            # generate packet from public to private ip or vice versa
            if (random.randint(0, 1) == 0):
                pkt = IP(src=ip_from_int_to_str(flow_list[flow_index][1]), dst=ip_from_int_to_str(NAT_PUBLIC_IP)) / TCP(sport=flow_list[flow_index][3], dport=port_list[flow_index], flags="A", seq=public_to_private[flow_index]+PAYLOAD_PER_PKT, ack=private_to_public[flow_index]) / Raw(load="A" * PAYLOAD_PER_PKT)
                public_to_private[flow_index] += PAYLOAD_PER_PKT
            else:
                pkt = IP(src=ip_from_int_to_str(flow_list[flow_index][0]), dst=ip_from_int_to_str(flow_list[flow_index][1])) / TCP(sport=flow_list[flow_index][2], dport=flow_list[flow_index][3], flags="A", seq=private_to_public[flow_index]+PAYLOAD_PER_PKT, ack=public_to_private[flow_index]) / Raw(load="A" * PAYLOAD_PER_PKT)
                private_to_public[flow_index] += PAYLOAD_PER_PKT
        #pkt.show()
        wrpcap(args.output, pkt, append=True)

