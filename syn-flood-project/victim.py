#!/usr/bin/env python3
"""
Victim server for the SYN flood lab demo (GUI / multi-page).

Serves a small real-looking website so denial of service is
visible in a browser, while keeping a deliberately small listen()
backlog so the SYN queue saturates quickly.

    /            -> web/index.html   (home, has a "Browse the Gallery" button)
    /cats.html   -> web/cats.html    (gallery page the button links to)

Pages live in the web/ folder next to this script, so you can
restyle them without touching this code. During the flood the
browser can't open a NEW connection, so clicking the button just
spins and never loads -> visible DoS.

Usage:
    sudo python3 victim.py [port] [backlog]     (default port=80 backlog=8)

Open in the LEGIT user's browser (from the other PC):
    http://<victim_ip>        e.g. http://172.24.0.79
NOT localhost / 127.0.0.1 -- that bypasses the network path.
"""
import socket
import sys
import os
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
BACKLOG = int(sys.argv[2]) if len(sys.argv) > 2 else 8
HOST = "0.0.0.0"

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")

# map URL path -> file inside web/
ROUTES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/cats.html": "cats.html",
}


def load_file(fname: str) -> bytes:
    try:
        with open(os.path.join(WEB, fname), "rb") as f:
            return f.read()
    except FileNotFoundError:
        return b"<html><body><h1>Service is UP</h1></body></html>"


def http_response(body: bytes, status="200 OK") -> bytes:
    head = (
        f"HTTP/1.1 {status}\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")
    return head + body


def parse_path(request: bytes) -> str:
    try:
        first = request.split(b"\r\n", 1)[0].decode("latin1")
        return first.split(" ")[1]
    except Exception:
        return "/"


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(BACKLOG)

print(f"[victim] listening on {HOST}:{PORT}  backlog={BACKLOG}")
print(f"[victim] serving pages from {WEB}  (/ and /cats.html)")
print(f"[victim] open  http://<victim_ip>  in the legit user's browser")
print("[victim] waiting for connections... (Ctrl+C to stop)")

while True:
    try:
        conn, addr = s.accept()
        ts = time.strftime("%H:%M:%S")
        try:
            request = conn.recv(1024)
            path = parse_path(request)
            fname = ROUTES.get(path.split("?")[0])
            if fname:
                conn.sendall(http_response(load_file(fname)))
                print(f"[victim] {ts}  {addr[0]} requested {path} -> {fname}")
            else:
                body = b"<html><body><h1>404 Not Found</h1></body></html>"
                conn.sendall(http_response(body, "404 Not Found"))
                print(f"[victim] {ts}  {addr[0]} requested {path} -> 404")
        except Exception:
            pass
        conn.close()
    except KeyboardInterrupt:
        print("\n[victim] stopping.")
        break