#!/usr/bin/env python3

import socket, sys, struct, re, os
from enum import IntFlag

def read_services():
    """
    Reads a services TSV file, sorts on rank, and then returns the top 1000 services

    You can use nmap-services or any TSV in the format:
    SERVICE_NAME\tPORT_NUMBER/PROTOCOL\tRANK
    """
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

def send_tcp_syn():
    dest = 'localhost'

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as msg:
        print('Socket error: %s' % msg)
        print('Requires root to create ICMP socket')
        exit(1)

    packet = ''
    
    dest_ip = socket.gethostbyname(dest)
    #source_ip = '10.0.0.244'
    source_ip = dest_ip
    source_port = 1234
    dest_port = 3000 
    source = (source_ip, source_port)
    dest = (dest_ip, dest_port)

    packet = TCPIPHeader(source = source, dest = dest, flags = TCPFlag.SYN).packet

    sock.sendto(packet, (dest_ip, 1))


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

class IPHeader:
    """IP Protocol Header"""
    def __init__(
            self,
            source_addr,
            dest_addr,
            total_len = 40,
            id = os.getpid() & 0xffff,
            flags = 0,
            frag_offset = 0,
            ttl = 255,
            protocol = socket.IPPROTO_TCP):
        """
        IP Header

        Version: 4 bits
        Internet Header Length (IHL): 4 bits
        Differentiated Services Code Point (DSCP/ToS): 6 bits
        Explicit Congestion Notification (ESN): 2 bits
        Total Length: 16 bits
        Identification: 16 bits
        Flags: 3 bits
        Fragment Offset: 13 bits
        TTL: 8 bits
        Protocol: 8 bits
        Checksum: 16 bits
        Source Address: 32 bits
        Destination Address: 32 bits
        """
        self.version = 4
        self.ihl = 5
        self.dscp = 0
        self.ecn = 0
        self.total_len = total_len 
        self.id = id
        self.flags = 0
        self.frag_offset = frag_offset
        self.ttl = ttl
        self.protocol = protocol
        self.cs = 0
        self.source = socket.inet_aton(source_addr)
        self.dest = socket.inet_aton(dest_addr)
        
        # Combine some fields to get 8 bit boundaries
        self.version_ihl = (self.version << 4) | (self.ihl & 0xff)
        self.dscp_ecn = (self.dscp << 2) | (self.ecn & 0xf)
        self.flags_frag_offset = (self.flags << 13) | (self.frag_offset & 0x1fff)

    def pack(self):
        """Pack the IP header values into a byte string"""
        header = struct.pack(
                "!BBHHHBBH4s4s",
                self.version_ihl,
                self.dscp_ecn,
                self.total_len,
                self.id,
                self.flags_frag_offset,
                self.ttl,
                self.protocol,
                self.cs,
                self.source,
                self.dest)

        self.cs = checksum(header)

        return struct.pack(
                "!BBHHHBBH4s4s",
                self.version_ihl,
                self.dscp_ecn,
                self.total_len,
                self.id,
                self.flags_frag_offset,
                self.ttl,
                self.protocol,
                self.cs,
                self.source,
                self.dest)

class TCPFlag(IntFlag):
    """
    TCP Flags
    """
    NS = 0x100
    CWR = 0x080
    ECE = 0x040
    URG = 0x020
    ACK = 0x010
    PSH = 0x008
    RST = 0x004
    SYN = 0x002
    FIN = 0x001

class TCPHeader:
    """TCP Protocol Header"""
    def __init__(self, source_port, dest_port, seq = 0, ack = 0, data_offset = 5, flags = 0, window = 5840):
        """
        # TCP Header
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
        """
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq = seq
        self.ack = ack
        self.data_offset = data_offset
        self.reserved = 0
        self.flags = flags
        self.window = socket.htons(window)
        self.cs = 0
        self.urgent_ptr = 0

        # Combine fields to get 8 bit boundary
        self.data_offset_flags = (self.data_offset << 12) | self.flags

    def pack(self, source_addr, dest_addr, protocol = socket.IPPROTO_TCP):
        """
        Packs TCP header values into a byte string

        Uses a pseudo header to calculate the checksum

        TCP Pseudo Header Layout:
        Source Address: 32 bits
        Destination Address: 32 bits
        Padding: 8 bits
        Protocol: 8 bits
        TCP Header Length (including Payload) in Bytes: 16 bits
        """
        source_ip = socket.inet_aton(source_addr)
        dest_ip = socket.inet_aton(dest_addr)

        header = struct.pack(
                "!HHLLHHHH",
                self.source_port,
                self.dest_port,
                self.seq,
                self.ack,
                self.data_offset_flags,
                self.window,
                self.cs,
                self.urgent_ptr)

        pseudo_header = struct.pack("!4s4sBBH", source_ip, dest_ip, 0, protocol, len(header))
        
        combined_header = pseudo_header + header

        self.cs = checksum(combined_header)

        return struct.pack(
                "!HHLLHHHH",
                self.source_port,
                self.dest_port,
                self.seq,
                self.ack,
                self.data_offset_flags,
                self.window,
                self.cs,
                self.urgent_ptr)

class TCPIPHeader:
    """
    Combined TCP/IP Header
    """
    def __init__(
            self,
            source,
            dest,
            id = os.getpid() & 0xffff,
            ttl = 255,
            seq = 0,
            ack = 0,
            flags = 0,
            window = 5840):
        """Concats a packed IP header with a packed TCP header with is stored in self.packet"""
        self.ip_header = IPHeader(
                source_addr = source[0],
                dest_addr = dest[0],
                id = id,
                ttl = ttl)
        ip_header_bytes = self.ip_header.pack()

        self.tcp_header = TCPHeader(
                source_port = source[1],
                dest_port = dest[1],
                seq = seq,
                ack = ack,
                flags = flags,
                window = window
                )
        tcp_header_bytes = self.tcp_header.pack(source_addr = source[0], dest_addr = dest[0])

        self.packet = ip_header_bytes + tcp_header_bytes

if __name__ == "__main__":
    send_tcp_syn()
