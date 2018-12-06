#!/usr/bin/env python3

import socket, sys, struct, re, os
from enum import IntFlag

def read_services():
    services = []
    f = open('data/pymap-services')
    for line in f:
        line = line.strip()
        if line[0] == "#":
            continue
        line = re.sub("\t*#.*$", "", line)
        services.append(re.split("\t|/", line))
    f.close()
    services.sort(key=lambda i: i[3], reverse=True)
    return services[:1000]

def checksum(data):
    """
    Calculate the 16 bit checksum for data
    """
    total = 0
    # Sum 16 bits chunks (the first byte * 256 + second byte)
    for i in range(len(data) - (len(data) % 2)):
        total += (data[i] << 8) if i % 2 else data[i]

    # Add in any remaining bits
    if len(data) % 2 != 0:
        total + data[-1]

    # Add in carry bits
    total = (total & 0xffff) + (total >> 16)
    total = total + (total >> 16)

    # Flip and change order
    total = ~total & 0xffff
    return total >> 8 | (total << 8 & 0xff00)

class TCP(IntFlag):
    NS = 0x100
    CWR = 0x080
    ECE = 0x040
    URG = 0x020
    ACK = 0x010
    PSH = 0x008
    RST = 0x004
    SYN = 0x002
    FIN = 0x001


def send_tcp_syn():
    dest = 'localhost'

    try:
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as msg:
        print('Socket error: %s' % msg)
        print('Requires root to create ICMP socket')
        exit(1)

    packet = ''
    
    dest_ip = socket.gethostbyname(dest)
    #source_ip = '10.0.0.244'
    source_ip = dest_ip

    # IP header fields
    # Version: 4 bits
    # Internet Header Length (IHL): 4 bits
    # Differentiated Services Code Point (DSCP/ToS): 6 bits
    # Explicit Congestion Notification (ESN): 2 bits
    # Total Length: 16 bits
    # Identification: 16 bits
    # Flags: 3 bits
    # Fragment Offset: 13 bits
    # TTL: 8 bits
    # Protocol: 8 bits
    # Checksum: 16 bits
    # Source Address: 32 bits
    # Destination Address: 32 bits
    ip_version = 4
    ip_ihl = 5
    ip_dscp = 0
    ip_ecn = 0
    ip_total_len = 40
    ip_id = os.getpid() & 0xffff
    ip_flags = 0
    ip_frag_offset = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_cs = 0
    ip_source_addr = socket.inet_aton(source_ip)
    ip_dest_addr = socket.inet_aton(dest_ip)

    ip_version_ihl = (ip_version << 4) | (ip_ihl & 0xff)
    ip_dscp_ecn = (ip_dscp << 2) | (ip_ecn & 0xf)
    ip_flags_frag_offset = (ip_flags << 13) | (ip_frag_offset & 0x1fff)

    print("!BBHHHBBHLL", ip_version_ihl, ip_dscp_ecn, ip_total_len, ip_id, ip_flags_frag_offset, ip_ttl, ip_proto, ip_cs, ip_source_addr, ip_dest_addr)
    ip_header = struct.pack("!BBHHHBBH4s4s", ip_version_ihl, ip_dscp_ecn, ip_total_len, ip_id, ip_flags_frag_offset, ip_ttl, ip_proto, ip_cs, ip_source_addr, ip_dest_addr)

    ip_cs = checksum(ip_header)

    ip_header = struct.pack("!BBHHHBBH4s4s", ip_version_ihl, ip_dscp_ecn, ip_total_len, ip_id, ip_flags_frag_offset, ip_ttl, ip_proto, ip_cs, ip_source_addr, ip_dest_addr)

    # TCP Header Fields
    # Source Port: 16 bits
    # Destination Port: 16 bits
    # Sequence Number: 32 bits
    # Acknowledgment Number (if ACK set): 32 bits
    # Data Offset in 32 bit words: 4 bits
    # Reserved: 3 bits
    # Flags: 9 bits
    # Window Size in Bytes: 16 bits
    # Checksum: 16 bits
    # Urgent Pointer: 16 bits
    # Options (if data offset > 5: padded at the end with "0" bytes): 0-320 bits, divisible by 32
    tcp_src_port = 1234
    tcp_dest_port = 3000 
    tcp_seq = 0
    tcp_ack_num = 0
    tcp_data_offset = 5
    tcp_reserved = 0
    tcp_flags = TCP.SYN
    tcp_window = socket.htons(5840)
    tcp_cs = 0
    tcp_urgent_ptr = 0

    tcp_data_offset_flags = (tcp_data_offset << 12) | tcp_flags

    print("!HHLLHHHH", tcp_src_port, tcp_dest_port, tcp_seq, tcp_ack_num, tcp_data_offset_flags, tcp_window, tcp_cs, tcp_urgent_ptr)
    tcp_header = struct.pack("!HHLLHHHH", tcp_src_port, tcp_dest_port, tcp_seq, tcp_ack_num, tcp_data_offset_flags, tcp_window, tcp_cs, tcp_urgent_ptr)

    # TCP Pseudo Header
    # Source Address: 32 bits
    # Destination Address: 32 bits
    # Padding: 8 bits
    # Protocol: 8 bits
    # TCP Header Length (including Payload) in Bytes: 16 bits
    tcp_pseudo_header = struct.pack("!4s4sBBH", ip_source_addr, ip_dest_addr, 0, socket.IPPROTO_TCP, len(tcp_header))
    
    tcp_cs_header = tcp_pseudo_header + tcp_header

    tcp_cs = checksum(tcp_cs_header)

    tcp_header = struct.pack("!HHLLHHHH", tcp_src_port, tcp_dest_port, tcp_seq, tcp_ack_num, tcp_data_offset_flags, tcp_window, tcp_cs, tcp_urgent_ptr)

    packet = ip_header + tcp_header

    print(packet)
    tcp_socket.sendto(packet, (dest_ip, 1))

if __name__ == "__main__":
    send_tcp_syn()
