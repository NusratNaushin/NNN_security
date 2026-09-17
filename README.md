# TCP SYN Flood + DoS Attack — CSE406 Design Project

Custom raw-socket SYN flood attack tool built from scratch (no hping3/Scapy/other
pre-built tools) for the CSE406 Computer Security Sessional design project.

Tested and working in a **Mininet** virtual environment (Phase 1). Phase 2
(two physical machines) is a separate, later step — see notes at the bottom.

## Files

| File | Purpose |
|---|---|
| `attacker.py` | Raw-socket SYN flood sender. Builds IP + TCP headers manually with `struct`, computes checksums ourselves. |
| `victim.py` | Simple TCP server with a deliberately small `listen()` backlog (default 8), so queue saturation is easy to observe. |
| `legit_client.py` | Simulates a legitimate client repeatedly connecting to the victim, logging success/fail and latency — this is how we *measure* denial of service, not just observe it. |

## Prerequisites (run once per machine)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential python3 python3-pip python3-venv \
    wireshark tcpdump net-tools iproute2 iptables netcat-openbsd \
    mininet ethtool
sudo usermod -aG wireshark $USER
```

Log out and log back in (or reboot) after this so the `wireshark` group membership
takes effect.

Verify Mininet works:
```bash
sudo mn --test pingall
```
Should show `0% dropped`.

## Project setup

```bash
mkdir -p ~/syn-flood-project
cd ~/syn-flood-project
# copy attacker.py, victim.py, legit_client.py into this folder
```

## Running the full demo (Mininet)

Everything below is typed **inside the `mininet>` prompt**, unless stated otherwise.
Replace `nidhi` with your own Linux username in every path.

### 1. Clean start
```bash
sudo mn -c                                   # (normal terminal, before starting mininet)
sudo mn --topo single,2 --mac --arp          # starts mininet, gives the mininet> prompt
```
This creates two hosts: `h1` (attacker, IP `10.0.0.1`) and `h2` (victim, IP `10.0.0.2`).

### 2. Required fixes — apply every time you start a fresh Mininet session

These are **not optional** — without them the attack will silently fail to work.
They reset every time Mininet restarts, so re-apply them each session.

```
h1 ethtool -K h1-eth0 tx off
h2 ethtool -K h2-eth0 rx off
```
> **Why:** the virtual NIC (veth) tries to "helpfully" recompute/offload the
> checksum on send/receive. Since we already compute a correct checksum
> ourselves, this offloading corrupts it, and the kernel silently drops the
> packet on arrival. Disabling offload stops this interference.

```
h2 sysctl -w net.ipv4.tcp_syncookies=0
h2 sysctl -w net.ipv4.conf.all.rp_filter=0
h2 sysctl -w net.ipv4.conf.h2-eth0.rp_filter=0
```
> **Why:** SYN cookies (on by default on many distros) bypass the backlog
> queue entirely, so it never fills up — this defeats the baseline attack
> before you can even demonstrate it. `rp_filter` is Linux's anti-spoofing
> "martian source" check; disabling it lets spoofed-source packets through.

```
h2 bash -c 'for i in $(seq 100 200); do ip neighbor add 10.0.0.$i lladdr 02:00:00:00:99:99 dev h2-eth0 nud permanent; done'
```
> **Why (the most important, non-obvious fix):** our attacker spoofs source
> IPs in the range `10.0.0.100`–`10.0.0.200`, which is on the **same local
> subnet** as the victim. When the victim tries to reply with SYN-ACK to a
> spoofed address, it first has to ARP-resolve that address. Since no real
> host exists at those IPs, ARP fails — and because this is a *directly
> connected* subnet (no router in between), Linux treats that ARP failure as
> an **immediate, synchronous "host unreachable"**, destroying the half-open
> connection instantly instead of leaving it in the backlog until timeout.
> Pre-loading a permanent (fake) ARP/neighbor entry for the whole spoofed
> range tricks the kernel into thinking the address is resolved, so it sends
> the SYN-ACK out normally (into the void) and the half-open connection
> correctly stays queued until it times out — exactly like a real remote
> spoofed address would behave.

### 3. Start the victim server
```
h2 python3 /home/nidhi/syn-flood-project/victim.py 80 8 &
h2 ss -tan
```
Confirm you see `LISTEN` on port 80.

### 4. Baseline test (before attack)
```
h1 python3 /home/nidhi/syn-flood-project/legit_client.py 10.0.0.2 80 5 2
```
Expect `5/5 SUCCESS`, ~0ms latency. This is your "before" number.

### 5. Launch the attack (once — don't run it twice by accident)
```
h1 python3 /home/nidhi/syn-flood-project/attacker.py 10.0.0.2 80 10.0.0 &
```
You should see `[attacker] sent N packets (rate pkt/s)` messages.

### 6. Verify the backlog is filling (the core evidence)
```
h2 ss -tan state syn-recv
```
You should now see several rows with `10.0.0.2:80` as local address and
spoofed IPs (`10.0.0.1xx`) as peer address — these are real half-open
connections sitting in the backlog queue.

### 7. Prove denial of service
```
h1 python3 /home/nidhi/syn-flood-project/legit_client.py 10.0.0.2 80 5 2
```
Expect `0/5 SUCCESS` (or much lower than baseline) while the attack is running.
This is your "after" / attack number.

### 8. Defense demo — SYN cookies
```
h2 sysctl -w net.ipv4.tcp_syncookies=1
h1 python3 /home/nidhi/syn-flood-project/legit_client.py 10.0.0.2 80 5 2
```
Success rate should recover (back toward `5/5`) — this demonstrates the
SYN-cookies defense working. Remember to set it back to `0` if you want to
re-run the baseline attack afterward.

### 9. Defense demo — rate limiting (iptables, optional)
```
h2 sysctl -w net.ipv4.tcp_syncookies=0
h2 iptables -A INPUT -p tcp --syn --dport 80 -m hashlimit --hashlimit-above 50/sec --hashlimit-mode srcip --hashlimit-name synflood -j DROP
```
Re-run the attack + legit_client to see partial recovery from rate limiting.

### 10. Cleanup
```
h1 pkill -9 -f attacker.py
h2 pkill -f victim.py
exit
```
If Mininet ever gets into a weird state, run `sudo mn -c` in a normal
terminal before starting again.

## Expected results summary

| Run | `SYN_RECV` count | Legit client success |
|---|---|---|
| Baseline (no attack, cookies off) | 0 | 5/5 (100%) |
| Under attack (cookies off) | ~8–9 (backlog full) | 0/5 (0%) |
| Under attack + SYN cookies | 0 | 5/5 (100%) |
| Under attack + rate limiting | low | partial recovery |

## Troubleshooting

- **`h1: command not found` / `bash: syntax error`** — you typed a command
  into the *normal* Linux terminal instead of the `mininet>` prompt (or
  copied stray backticks/prompt text along with the command). Only type the
  plain command text shown above, and only after you see `mininet>`.
- **`Address already in use` when starting `victim.py`** — a previous
  `victim.py` is already running and holding port 80. This is often harmless
  (the first instance is still running fine); confirm with `h2 ss -tan`.
- **`ethtool: command not found`** — install it: `sudo apt install ethtool -y`,
  then restart Mininet.
- **Backlog stays at 0 / `ss -tan state syn-recv` shows nothing despite the
  attack running** — almost always one of: (a) SYN cookies still on, (b) the
  ARP pre-load step (2) wasn't run for the *current* Mininet session, or (c)
  checksum offload wasn't disabled. Re-check step 2 in full; it must be
  re-applied every time Mininet restarts.
- **`legit_client.py` shows 100% success even under attack** — check
  `h2 sysctl net.ipv4.tcp_syncookies`; if it's `1`, a previous defense-demo
  step left it on. Set it back to `0` and re-run the attack.

## Moving to Phase 2 (two physical machines)

The same three scripts work unchanged on real machines — only the network
setup changes:
1. Connect both PCs to the same LAN/switch (or router).
2. Find each machine's real IP (`ip addr`) and make sure they can `ping`
   each other.
3. Run `victim.py` on the victim PC, `attacker.py <victim's real IP> 80 <victim's subnet prefix>`
   on the attacker PC.
4. Re-apply the same fixes (steps 2.1–2.4 above) using the real interface
   names (`ip addr` shows these, e.g. `eth0` or `wlan0` instead of `h1-eth0`).
