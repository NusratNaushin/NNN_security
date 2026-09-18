#!/usr/bin/env python3
"""
dashboard.py -- live SYN-flood monitor for the VICTIM PC.

Samples the kernel once per second and serves a compact monitoring
page (no external libraries, no frameworks). Shows:
  - listen backlog vs current half-open (SYN_RECV) count
  - a rolling time-series sparkline of the half-open count
  - incoming SYN rate (packets/sec, derived from the /proc counters)
  - number of distinct (spoofed) source IPs and the busiest ones
  - current kernel defense state (tcp_syncookies on/off)

It only reads state (`ss`, /proc, sysctl); it never changes anything.

Usage (victim PC):
    python3 dashboard.py [backlog] [port]      # defaults: 8, 8080
    # then open http://localhost:8080 on the victim PC
"""
import http.server
import socketserver
import subprocess
import collections
import json
import sys
import time

BACKLOG   = int(sys.argv[1]) if len(sys.argv) > 1 else 8
DASH_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080

# rolling history of half-open counts (for the sparkline)
HISTORY_LEN = 60
history = collections.deque([0] * HISTORY_LEN, maxlen=HISTORY_LEN)

# for SYN-rate calculation from /proc/net/snmp (TcpExt / Tcp: passive opens etc.)
_last = {"t": time.time(), "segs": None}


def syn_recv_rows():
    try:
        out = subprocess.check_output(["ss", "-tan", "state", "syn-recv"],
                                      text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []
    rows = []
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) >= 4 and ":" in p[3]:
            ip, _, port = p[3].rpartition(":")
            rows.append((ip, port))
    return rows


def tcp_in_segs():
    """Total received TCP segments (for a rough incoming-rate gauge)."""
    try:
        with open("/proc/net/snmp") as f:
            lines = f.read().splitlines()
        hdr = val = None
        for i, ln in enumerate(lines):
            if ln.startswith("Tcp:") and "InSegs" in ln:
                hdr = ln.split()
                val = lines[i + 1].split()
                break
        if hdr and val:
            idx = hdr.index("InSegs")
            return int(val[idx])
    except Exception:
        pass
    return None


def syncookies_on():
    try:
        with open("/proc/sys/net/ipv4/tcp_syncookies") as f:
            return f.read().strip() == "1"
    except Exception:
        return None


def sample():
    rows = syn_recv_rows()
    count = len(rows)
    history.append(count)

    by_src = collections.Counter(ip for ip, _ in rows)
    top = by_src.most_common(6)

    # incoming segment rate
    now = time.time()
    segs = tcp_in_segs()
    rate = None
    if segs is not None and _last["segs"] is not None:
        dt = now - _last["t"]
        if dt > 0:
            rate = max(0, int((segs - _last["segs"]) / dt))
    _last["t"] = now
    _last["segs"] = segs

    return {
        "backlog": BACKLOG,
        "count": count,
        "distinct": len(by_src),
        "top": top,
        "history": list(history),
        "seg_rate": rate,
        "cookies": syncookies_on(),
        "ts": time.strftime("%H:%M:%S"),
    }


PAGE = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SYN Flood Monitor — victim</title>
<style>
 :root{
   --bg:#0b0f14; --panel:#121821; --panel2:#0e141c; --line:#1f2a36;
   --ink:#dbe4ee; --muted:#7688a0; --accent:#3b82f6;
   --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444;
 }
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--ink);
   font-family:'SF Mono',ui-monospace,'Cascadia Code',Menlo,Consolas,monospace;
   font-size:13px;line-height:1.5}
 .top{display:flex;align-items:center;justify-content:space-between;
   padding:12px 18px;border-bottom:1px solid var(--line);background:var(--panel2)}
 .title{font-weight:700;font-size:14px;letter-spacing:.3px}
 .title small{color:var(--muted);font-weight:400;margin-left:8px}
 .clock{color:var(--muted)}
 .grid{display:grid;grid-template-columns:1.1fr 1fr;gap:14px;padding:18px;max-width:1000px;margin:0 auto}
 .panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
 .panel h2{margin:0 0 12px;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--muted);font-weight:600}
 .big{display:flex;align-items:baseline;gap:10px}
 .big .n{font-size:40px;font-weight:700;font-variant-numeric:tabular-nums}
 .big .d{color:var(--muted);font-size:15px}
 .state{margin-top:10px;font-weight:700;padding:6px 10px;border-radius:6px;display:inline-block;font-size:12px}
 .s-ok{background:rgba(34,197,94,.12);color:var(--ok)}
 .s-warn{background:rgba(245,158,11,.12);color:var(--warn)}
 .s-bad{background:rgba(239,68,68,.12);color:var(--bad)}
 .bar{height:8px;background:#0a0f16;border-radius:4px;overflow:hidden;margin-top:14px;border:1px solid var(--line)}
 .bar > i{display:block;height:100%;width:0;background:linear-gradient(90deg,#f59e0b,#ef4444);transition:width .3s}
 table{width:100%;border-collapse:collapse;margin-top:2px}
 th,td{text-align:left;padding:5px 6px;font-variant-numeric:tabular-nums}
 th{color:var(--muted);font-weight:600;font-size:11px;border-bottom:1px solid var(--line)}
 td.ip{color:var(--ink)} td.c{text-align:right;color:var(--warn)}
 .metrics{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:4px}
 .metric{background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:10px 12px}
 .metric .k{color:var(--muted);font-size:11px}
 .metric .v{font-size:20px;font-weight:700;margin-top:2px;font-variant-numeric:tabular-nums}
 svg{display:block;width:100%;height:90px;margin-top:6px}
 .foot{color:var(--muted);text-align:center;padding:10px;font-size:11px;border-top:1px solid var(--line)}
 .dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;vertical-align:middle}
</style></head><body>
<div class="top">
  <div class="title">SYN-FLOOD MONITOR <small>victim · port 80 · backlog __BACKLOG__</small></div>
  <div class="clock"><span class="dot" id="live"></span><span id="clock">--:--:--</span></div>
</div>

<div class="grid">
  <div class="panel">
    <h2>Backlog saturation</h2>
    <div class="big"><span class="n" id="count">0</span><span class="d">/ __BACKLOG__ half-open</span></div>
    <div id="state" class="state s-ok">IDLE — no half-open connections</div>
    <div class="bar"><i id="fill"></i></div>
    <h2 style="margin-top:18px">Half-open history (last 60s)</h2>
    <svg id="spark" viewBox="0 0 300 90" preserveAspectRatio="none"></svg>
  </div>

  <div class="panel">
    <h2>Live metrics</h2>
    <div class="metrics">
      <div class="metric"><div class="k">Distinct source IPs</div><div class="v" id="distinct">0</div></div>
      <div class="metric"><div class="k">Incoming TCP seg/s</div><div class="v" id="rate">–</div></div>
      <div class="metric"><div class="k">Queue utilisation</div><div class="v" id="util">0%</div></div>
      <div class="metric"><div class="k">SYN cookies (defense)</div><div class="v" id="cookies">?</div></div>
    </div>
    <h2 style="margin-top:18px">Top spoofed sources (half-open)</h2>
    <table><thead><tr><th>Source IP</th><th style="text-align:right">Half-open</th></tr></thead>
      <tbody id="rows"><tr><td class="ip" style="color:var(--muted)">— none —</td><td class="c"></td></tr></tbody>
    </table>
  </div>
</div>
<div class="foot">CSE406 — TCP SYN Flood &amp; DoS · read-only monitor (ss + /proc) · refresh 1s</div>

<script>
const BACKLOG = __BACKLOG__;
let blink = true;

function spark(hist){
  const w=300,h=90,max=Math.max(BACKLOG, ...hist, 1);
  const step=w/(hist.length-1);
  let d="";
  hist.forEach((v,i)=>{ const x=i*step, y=h-(v/max)*(h-6)-3; d+=(i?"L":"M")+x.toFixed(1)+" "+y.toFixed(1)+" "; });
  // baseline area
  const area=d+`L ${w} ${h} L 0 ${h} Z`;
  const thr=h-(BACKLOG/max)*(h-6)-3;
  return `<path d="${area}" fill="rgba(239,68,68,.10)"/>`
       + `<line x1="0" y1="${thr.toFixed(1)}" x2="${w}" y2="${thr.toFixed(1)}" stroke="#f59e0b" stroke-width="1" stroke-dasharray="4 4" opacity=".7"/>`
       + `<path d="${d}" fill="none" stroke="#ef4444" stroke-width="1.6"/>`;
}

async function tick(){
  document.getElementById('live').style.background = (blink=!blink) ? 'var(--ok)' : 'transparent';
  try{
    const d = await (await fetch('/data',{cache:'no-store'})).json();
    document.getElementById('clock').textContent = d.ts;
    document.getElementById('count').textContent = d.count;
    document.getElementById('distinct').textContent = d.distinct;
    document.getElementById('rate').textContent = (d.seg_rate==null?'–':d.seg_rate);
    const util = Math.round(100*d.count/BACKLOG);
    document.getElementById('util').textContent = util+'%';
    document.getElementById('fill').style.width = Math.min(100,util)+'%';

    const ck = document.getElementById('cookies');
    if(d.cookies===true){ ck.textContent='ON'; ck.style.color='var(--ok)'; }
    else if(d.cookies===false){ ck.textContent='OFF'; ck.style.color='var(--bad)'; }
    else { ck.textContent='?'; ck.style.color='var(--muted)'; }

    const st=document.getElementById('state');
    if(d.count>=BACKLOG){ st.className='state s-bad'; st.textContent='SATURATED — backlog full, new SYNs at risk of drop'; }
    else if(d.count>0){ st.className='state s-warn'; st.textContent='ELEVATED — half-open connections building up'; }
    else { st.className='state s-ok'; st.textContent='IDLE — no half-open connections'; }

    document.getElementById('spark').innerHTML = spark(d.history);

    const tb=document.getElementById('rows');
    if(d.top.length){
      tb.innerHTML = d.top.map(([ip,c])=>`<tr><td class="ip">${ip}</td><td class="c">${c}</td></tr>`).join('');
    } else {
      tb.innerHTML = '<tr><td class="ip" style="color:var(--muted)">— none —</td><td class="c"></td></tr>';
    }
  }catch(e){}
}
tick(); setInterval(tick,1000);
</script>
</body></html>""".replace("__BACKLOG__", str(BACKLOG))


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/data"):
            payload = json.dumps(sample()).encode()
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


print(f"[dashboard] backlog={BACKLOG}  open http://localhost:{DASH_PORT} on the victim PC")
with socketserver.TCPServer(("127.0.0.1", DASH_PORT), Handler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] stopping.")