#!/usr/bin/env python3
"""
Simulates a legitimate client repeatedly trying to connect to the
victim, so we can measure success rate and latency (per the
Measurement Plan in the design report) while the flood is running.

Usage:
    python3 legit_client.py <victim_ip> [victim_port] [num_tries] [timeout_seconds]
"""
import socket
import sys
import time

victim_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
victim_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
num_tries = int(sys.argv[3]) if len(sys.argv) > 3 else 20
timeout_s = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0

success = 0
fail = 0
latencies = []

print(f"[legit_client] trying to connect to {victim_ip}:{victim_port}, {num_tries} attempts, timeout={timeout_s}s")

for i in range(1, num_tries + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    start = time.time()
    try:
        s.connect((victim_ip, victim_port))
        elapsed = time.time() - start
        latencies.append(elapsed)
        success += 1
        print(f"  attempt {i}: SUCCESS  ({elapsed*1000:.0f} ms)")
        s.close()
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        elapsed = time.time() - start
        fail += 1
        print(f"  attempt {i}: FAILED   ({elapsed*1000:.0f} ms)  [{e}]")
    time.sleep(0.2)

print()
print(f"[legit_client] success = {success}/{num_tries}  ({100*success/num_tries:.0f}%)")
if latencies:
    avg_latency = sum(latencies) / len(latencies)
    print(f"[legit_client] avg latency of successful connects = {avg_latency*1000:.0f} ms")
