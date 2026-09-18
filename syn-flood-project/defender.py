#!/usr/bin/env python3
"""
defender.py -- a custom, code-based SYN-flood defense for the CSE406
project. Runs ONLY on the VICTIM PC.

Idea (our own detection + response, not just a kernel switch):
  1. Every INTERVAL seconds, read the kernel's half-open (SYN_RECV)
     connections with `ss` and count how many each SOURCE IP has.
  2. Any source IP with more than THRESHOLD half-open connections is
     treated as an attacker and BLOCKED with an iptables DROP rule.
  3. Blocks auto-expire after BLOCK_SECONDS so a source that stops
     misbehaving is allowed back (mimics a real adaptive firewall).

This shows *why* a per-source defense only partially works against a
flood that spoofs a fresh source IP per packet: each spoofed IP makes
only a few half-open connections, so few cross the threshold. That
limitation is itself a good result to report.

Usage (victim PC, needs root for iptables):
    sudo python3 defender.py [threshold] [interval_sec] [block_sec]
    # defaults: threshold=3  interval=1.0  block=30

Stop with Ctrl+C -- it removes all rules it added on exit.
"""
import subprocess
import collections
import time
import sys
import signal

THRESHOLD   = int(sys.argv[1]) if len(sys.argv) > 1 else 3
INTERVAL    = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
BLOCK_SECS  = int(sys.argv[3]) if len(sys.argv) > 3 else 30
CHAIN_TAG   = "SYNDEF"   # comment tag so we can find/clean our own rules

# ip -> unix time when the block should be lifted
blocked = {}


def half_open_counts():
    """Return {src_ip: count} of current SYN_RECV connections."""
    try:
        out = subprocess.check_output(
            ["ss", "-tan", "state", "syn-recv"],
            text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return {}
    counts = collections.Counter()
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and ":" in parts[3]:
            ip = parts[3].rpartition(":")[0]
            counts[ip] += 1
    return counts


def block_ip(ip):
    subprocess.call([
        "iptables", "-I", "INPUT", "-s", ip, "-p", "tcp", "--dport", "80",
        "-m", "comment", "--comment", CHAIN_TAG, "-j", "DROP"
    ])
    print(f"[defender] BLOCK  {ip}  (had > {THRESHOLD} half-open)")


def unblock_ip(ip):
    subprocess.call([
        "iptables", "-D", "INPUT", "-s", ip, "-p", "tcp", "--dport", "80",
        "-m", "comment", "--comment", CHAIN_TAG, "-j", "DROP"
    ])
    print(f"[defender] unblock {ip}")


def cleanup(*_):
    print("\n[defender] cleaning up all rules we added...")
    for ip in list(blocked):
        unblock_ip(ip)
    print("[defender] done. bye.")
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

print(f"[defender] watching backlog every {INTERVAL}s | "
      f"threshold={THRESHOLD} half-open/src | block={BLOCK_SECS}s")
print("[defender] Ctrl+C to stop and remove all rules.\n")

while True:
    now = time.time()

    # 1) lift expired blocks
    for ip in list(blocked):
        if now >= blocked[ip]:
            unblock_ip(ip)
            del blocked[ip]

    # 2) find offenders and block them
    counts = half_open_counts()
    total = sum(counts.values())
    offenders = {ip: c for ip, c in counts.items() if c > THRESHOLD}

    for ip, c in offenders.items():
        if ip not in blocked:
            block_ip(ip)
        blocked[ip] = now + BLOCK_SECS   # (re)arm the timer

    print(f"[defender] half-open total={total:<3}  distinct-src={len(counts):<3}  "
          f"over-threshold={len(offenders):<3}  currently-blocked={len(blocked)}")

    time.sleep(INTERVAL)