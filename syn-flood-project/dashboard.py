#!/usr/bin/env python3
"""
Live backlog monitor dashboard for the SYN flood demo.
Runs ONLY on the VICTIM PC. It samples the kernel's SYN-RECV
(half-open) connections with `ss` once per second and shows them
in a browser as a live gauge + list of spoofed peer IPs.

It does NOT touch victim.py / attacker.py -- it just watches.

Usage (on the victim PC):
    python3 dashboard.py [backlog] [dashboard_port]
    # backlog defaults to 8 (match your victim.py), port defaults to 8080

Then open in a browser on the victim PC:
    http://localhost:8080
"""
import http.server
import socketserver
import subprocess
import json
import sys

BACKLOG = int(sys.argv[1]) if len(sys.argv) > 1 else 8
DASH_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080


def get_syn_recv():
    """Return list of (peer_ip, peer_port) currently in SYN-RECV."""
    try:
        out = subprocess.check_output(
            ["ss", "-tan", "state", "syn-recv"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []
    peers = []
    for line in out.splitlines()[1:]:          # skip header
        parts = line.split()
        if len(parts) >= 4:
            peer = parts[3]                     # e.g. 172.24.0.115:30097
            if ":" in peer:
                ip, _, port = peer.rpartition(":")
                peers.append((ip, port))
    return peers


PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Victim Backlog Monitor</title>
<style>
  body { margin:0; font-family:system-ui,sans-serif; background:#0f141a; color:#e7edf3;
         min-height:100vh; display:flex; align-items:center; justify-content:center; }
  .wrap { width:520px; max-width:92vw; }
  h1 { font-size:20px; text-align:center; margin:0 0 4px; }
  .subtitle { text-align:center; color:#7d8b99; font-size:13px; margin-bottom:22px; }
  .status { text-align:center; font-size:22px; font-weight:700; padding:10px; border-radius:12px; margin-bottom:18px; }
  .ok   { background:#12351f; color:#4ade80; }
  .bad  { background:#3a1620; color:#f87171; }
  .barwrap { background:#1b232c; border-radius:12px; height:46px; overflow:hidden; position:relative; margin-bottom:6px; }
  .bar { height:100%; width:0%; background:linear-gradient(90deg,#f59e0b,#ef4444); transition:width .3s ease; }
  .barlabel { position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
              font-weight:700; font-size:16px; }
  .count { text-align:center; color:#9fb0c0; font-size:13px; margin-bottom:20px; }
  .ips-title { font-size:13px; color:#7d8b99; margin-bottom:8px; }
  .ips { display:flex; flex-wrap:wrap; gap:6px; min-height:60px; }
  .chip { background:#1b232c; border:1px solid #2a3644; border-radius:8px;
          padding:5px 9px; font-size:12px; font-variant-numeric:tabular-nums; color:#cbd5e1; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>🛡️ Victim Backlog Monitor</h1>
    <div class="subtitle">CSE406 — TCP SYN Flood live view · port 80 · backlog __BACKLOG__</div>
    <div id="status" class="status ok">🟢 HEALTHY</div>
    <div class="barwrap"><div id="bar" class="bar"></div>
      <div id="barlabel" class="barlabel">0 / __BACKLOG__</div></div>
    <div class="count" id="count">half-open connections: 0</div>
    <div class="ips-title">spoofed half-open peers:</div>
    <div class="ips" id="ips"></div>
  </div>
<script>
const BACKLOG = __BACKLOG__;
async function refresh(){
  try{
    const r = await fetch('/data');
    const d = await r.json();
    const n = d.count;
    const pct = Math.min(100, Math.round(100*n/BACKLOG));
    document.getElementById('bar').style.width = pct+'%';
    document.getElementById('barlabel').textContent = n + ' / ' + BACKLOG;
    document.getElementById('count').textContent = 'half-open connections: ' + n;
    const st = document.getElementById('status');
    if(n >= BACKLOG){ st.className='status bad'; st.textContent='🔴 UNDER ATTACK — QUEUE FULL'; }
    else if(n > 0){ st.className='status bad'; st.textContent='🟠 SYN packets arriving...'; }
    else { st.className='status ok'; st.textContent='🟢 HEALTHY'; }
    const box = document.getElementById('ips');
    box.innerHTML='';
    d.peers.forEach(p=>{
      const c=document.createElement('div'); c.className='chip';
      c.textContent=p[0]+':'+p[1]; box.appendChild(c);
    });
  }catch(e){}
}
refresh(); setInterval(refresh, 1000);
</script>
</body>
</html>""".replace("__BACKLOG__", str(BACKLOG))


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence noisy logs
        pass

    def do_GET(self):
        if self.path == "/data":
            peers = get_syn_recv()
            payload = json.dumps({"count": len(peers), "peers": peers}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


print(f"[dashboard] backlog={BACKLOG}")
print(f"[dashboard] open  http://localhost:{DASH_PORT}  in a browser ON THE VICTIM PC")
print("[dashboard] Ctrl+C to stop")
with socketserver.TCPServer(("127.0.0.1", DASH_PORT), Handler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] stopping.")