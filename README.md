# TCP SYN Flood + DoS Attack — CSE406 Design Project

Custom raw-socket SYN flood tool built from scratch (no hping3 / Scapy /
other pre-built tools) for the CSE406 Computer Security Sessional.

Works between **two real machines on the same LAN / hotspot** (Phase 2).
Your PC is the **victim**, your friend's PC is the **attacker + legitimate
client**.

> ⚠️ Only run this on a network you control, ideally a hotspot with **only
> your two machines connected**. Spoofed packets and a flood on a shared
> Wi-Fi will disturb other users and can break the demo (see Troubleshooting).

## Folder structure

```
syn-flood-project/
├── attacker.py       # raw-socket SYN flood (single-thread)
├── attacker2.py      # multi-thread version (higher rate) — for the browser demo
├── victim.py         # small web server, deliberately small listen() backlog
├── legit_client.py   # measures DoS: connects repeatedly, logs success/latency
├── dashboard.py      # OPTIONAL live backlog monitor (victim PC only)
├── web/              # the website the victim serves
│   ├── index.html    # home page with a "Browse the Gallery" button
│   └── cats.html     # gallery page the button links to (dynamic)
└── README.md
```

## Files

| File | Runs on | Purpose |
|---|---|---|
| `attacker.py` | attacker PC | Builds IP + TCP headers manually with `struct`, computes checksums, floods spoofed SYNs. |
| `attacker2.py` | attacker PC | Same, but multi-threaded for a higher packet rate. Use when the browser demo drains the queue too fast. |
| `victim.py` | victim PC | Serves `web/` over HTTP with a tiny `listen()` backlog (default 8) so the SYN queue saturates fast. |
| `legit_client.py` | attacker PC | A legitimate client — how we *measure* denial of service (success rate + latency). |
| `dashboard.py` | victim PC | Optional browser dashboard showing the half-open queue filling live. |
| `web/index.html`, `web/cats.html` | served by victim | A small real-looking cat website; the button fails to load during the attack. |

## Key idea (one paragraph)

TCP sets up a connection with a 3-way handshake: SYN → SYN-ACK → ACK. When a
SYN arrives, the server puts a **half-open** entry in its SYN backlog queue and
waits for the final ACK. The attacker sends many SYNs with **spoofed source
IPs** and never sends the ACK, so each half-open entry sits in the queue until
it times out. Send them fast enough and the queue stays full, so **new SYNs
from real clients are dropped → denial of service.**

## Before you start — pick your IPs and a spoof range

Run `ip addr` on both machines and note the interface (e.g. `wlo1`) and IP.

Example used below (**substitute your own on the day**):

| Machine | Role | IP | Interface |
|---|---|---|---|
| Your PC | victim | `172.24.0.79` | `wlo1` |
| Friend's PC | attacker + legit | `172.24.0.164` | `wlo1` |

- **Spoof range** = last octets used for the fake source IPs. Set it to a range
  that contains **none of the real devices** on the subnet.
- Check what's actually in use first:
  ```bash
  ip neighbor show          # any real MAC in your intended range = pick another range
  ```
- The example below uses **`180–200`**. This range appears in TWO places and
  they **must match**: `LO, HI` at the top of `attacker.py` / `attacker2.py`,
  and the victim's ARP pre-load loop.

## Prerequisites (once per machine)

```bash
sudo apt update
sudo apt install -y python3 iproute2 ethtool net-tools tcpdump
```

---

## Running the demo

### 1. VICTIM PC — setup + start the server

```bash
cd ~/syn-flood-project

sudo ufw disable                                   # firewall off for the test
sudo ethtool -K wlo1 rx off                        # stop NIC checksum offload (ok if it says "cannot change")
sudo sysctl -w net.ipv4.tcp_syncookies=0           # baseline: defense OFF
sudo sysctl -w net.ipv4.conf.all.rp_filter=0       # allow spoofed sources
sudo sysctl -w net.ipv4.conf.wlo1.rp_filter=0

# pre-load fake ARP entries for the spoof range (MUST match attacker LO-HI)
sudo bash -c 'for i in $(seq 180 200); do ip neighbor replace 172.24.0.$i lladdr 02:00:00:00:99:99 dev wlo1 nud permanent; done'

# start the web server (small backlog = 8)
sudo pkill -f victim.py 2>/dev/null
sudo python3 victim.py 80 8 &
ss -tan | grep :80                                 # expect: LISTEN 0 8 0.0.0.0:80
```

> **Why each fix matters**
> - **checksum offload off:** the NIC re-computes checksums and corrupts the ones we built, so the kernel drops our packets.
> - **syncookies=0:** with cookies ON the backlog never fills — that's the defense; turn OFF for the baseline attack.
> - **rp_filter=0:** Linux's anti-spoofing check; disabling it lets spoofed sources through.
> - **ARP pre-load (most important):** on the same subnet the victim ARPs for each spoofed IP before sending SYN-ACK. Nobody answers, so Linux marks it "host unreachable" and drops the half-open entry instantly. A fake permanent ARP entry makes the kernel think the address is resolved, so SYN-ACK goes out (into the void) and the half-open connection correctly stays queued — exactly like a remote spoofed IP.

### 2. ATTACKER PC — setup

```bash
cd ~/syn-flood-project
sudo ethtool -K wlo1 tx off                        # stop send-side checksum offload
# make sure LO, HI at the top of the attacker script = your spoof range (180, 200)
```

### 3. Baseline (before attack) — ATTACKER PC

```bash
python3 legit_client.py 172.24.0.79 80 5 2         # expect 5/5 SUCCESS
```
Also open `http://172.24.0.79` in the friend's browser → the cat site loads,
and the **Browse the Gallery** button works. This is your "before".

### 4. Launch the attack — ATTACKER PC

```bash
# single-thread:
sudo python3 attacker.py 172.24.0.79 80 172.24.0 &
# OR, if the browser demo drains the queue, use more threads:
sudo python3 attacker2.py 172.24.0.79 80 172.24.0 16 &
```

### 5. Show the backlog filling — VICTIM PC (the core evidence)

```bash
ss -tan state syn-recv                 # rows with spoofed 172.24.0.18x peers
ss -tan state syn-recv | wc -l         # ~8-9 = queue full
sudo dmesg | grep -i syn               # "Possible SYN flooding on port 80"
```
Optional live view: `python3 dashboard.py 8` then open `http://localhost:8080`.

### 6. Prove denial of service — ATTACKER PC (while the attack runs)

```bash
python3 legit_client.py 172.24.0.79 80 5 2         # expect 0/5 SUCCESS
```
In the browser, click **Browse the Gallery** → it just spins and never loads.
"before 5/5 + site works" vs "after 0/5 + site down" = your DoS proof.

### 7. Defense demo — VICTIM PC (attack still running)

```bash
sudo sysctl -w net.ipv4.tcp_syncookies=1           # turn defense ON
```
Then, ATTACKER PC:
```bash
python3 legit_client.py 172.24.0.79 80 5 2         # recovers toward 5/5
```
The dashboard may still show the queue "full" (spoofed SYNs keep arriving), but
legit clients now succeed — that is exactly SYN cookies working: the queue can
be full yet real clients are let in via the cookie, so full no longer means
blocked. To re-run the baseline attack later, set it back to `=0`.

### 8. Cleanup (restore everything)

```bash
# ATTACKER PC
sudo pkill -9 -f attacker
sudo ethtool -K wlo1 tx on

# VICTIM PC
sudo pkill -f victim.py
sudo ip neighbor flush dev wlo1
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.wlo1.rp_filter=1
sudo ethtool -K wlo1 rx on
sudo ufw enable
```
Everything above is runtime-only — a **reboot** of both machines also restores
defaults (then just `sudo ufw enable`).

## Expected results

| Run | `SYN_RECV` count | Legit success | Browser |
|---|---|---|---|
| Baseline (no attack, cookies off) | 0 | 5/5 (100%) | site + button work |
| Under attack (cookies off) | ~8–9 (full) | 0/5 (0%) | button won't load |
| Under attack + SYN cookies | still ~8–9 | back to 5/5 | site works again |

## Troubleshooting

- **`ss ... syn-recv` stays empty / attack does nothing** — usually one of:
  (a) syncookies still `=1`, (b) ARP entries missing or gone `FAILED`
  (re-run the `ip neighbor replace` loop; check `ip neighbor show dev wlo1`),
  (c) checksum offload not disabled on the sender.
- **ARP entries show `FAILED`** — re-apply them with `ip neighbor replace`
  (not `add`, which errors with "File exists"). They can turn `FAILED` after a
  reboot or long idle; just replace them again.
- **A real device sits inside your spoof range** (e.g. `ip neighbor show` lists
  a real MAC at `172.24.0.101`) — it will send RST and weaken the attack. Move
  the spoof range (both the attacker `LO/HI` and the ARP loop) to empty
  addresses, or use a hotspot with only your two machines.
- **Legit client shows 100% even under attack** — check
  `sysctl net.ipv4.tcp_syncookies`; if `1`, a defense step left it on. Set `=0`.
- **Browser button sometimes still loads under attack** — the victim's
  `accept()` drains the queue; raise the rate with `attacker2.py 16` (or more
  threads).
- **`ethtool: cannot change ... rx-checksum`** — some Wi-Fi cards lock this;
  it's usually fine. Make sure the **attacker's** `tx off` worked, and just try
  the attack; if the queue fills, ignore the warning.