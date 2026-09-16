#!/usr/bin/env python3
"""
Victim server for the SYN flood lab demo.
Runs a plain TCP listener with a deliberately small backlog
so the queue-saturation effect is easy to reproduce and see.

Usage:
    python3 victim.py [port] [backlog]

Default: port=80, backlog=8
"""
import socket
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
BACKLOG = int(sys.argv[2]) if len(sys.argv) > 2 else 8
HOST = "0.0.0.0"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(BACKLOG)

print(f"[victim] listening on {HOST}:{PORT}  backlog={BACKLOG}")
print("[victim] waiting for connections... (Ctrl+C to stop)")

while True:
    try:
        conn, addr = s.accept()
        ts = time.strftime("%H:%M:%S")
        print(f"[victim] {ts}  accepted connection from {addr}")
        conn.close()
    except KeyboardInterrupt:
        print("\n[victim] stopping.")
        break
