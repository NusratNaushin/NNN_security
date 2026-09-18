#!/usr/bin/env bash
#
# setup_victim.sh — one-shot victim setup for the SYN flood demo.
# Run on the VICTIM PC after every boot / hotspot reconnect:
#     sudo bash setup_victim.sh
#
# It auto-detects your interface + IP, applies all the runtime fixes
# (firewall off, checksum offload off, syncookies off, rp_filter off,
# fake ARP entries for the spoof range), then starts victim.py.
# Optionally starts the dashboard too.
#
# Edit the two settings below if your subnet / range ever changes.

# ---- settings you can change ----
SPOOF_LO=180          # spoof range low  octet  (must match attacker LO)
SPOOF_HI=200          # spoof range high octet  (must match attacker HI)
PORT=80
BACKLOG=8
FAKE_MAC="02:00:00:00:99:99"
START_DASHBOARD=1     # 1 = also start dashboard.py, 0 = don't
# ---------------------------------

# must be root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run with sudo:  sudo bash setup_victim.sh"
    exit 1
fi

cd "$(dirname "$0")" || exit 1

# --- detect the Wi-Fi/ethernet interface that has the default route ---
IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
if [ -z "$IFACE" ]; then
    IFACE=$(ip -o link show | awk -F': ' '$2 !~ /lo|docker|veth|br-/ {print $2; exit}')
fi

# --- detect this machine's IPv4 on that interface ---
MYIP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1)
if [ -z "$MYIP" ]; then
    echo "Could not detect an IP on interface '$IFACE'. Are you connected to the hotspot?"
    exit 1
fi

# --- derive subnet prefix (first three octets), e.g. 172.24.0 ---
PREFIX=$(echo "$MYIP" | cut -d. -f1-3)
MY_OCTET=$(echo "$MYIP" | cut -d. -f4)

echo "=============================================="
echo " Interface : $IFACE"
echo " Victim IP : $MYIP"
echo " Subnet    : ${PREFIX}.0/24"
echo " Spoof     : ${PREFIX}.${SPOOF_LO}-${SPOOF_HI}"
echo "=============================================="

# --- warn if the victim's own IP is inside the spoof range ---
if [ "$MY_OCTET" -ge "$SPOOF_LO" ] && [ "$MY_OCTET" -le "$SPOOF_HI" ]; then
    echo "!! WARNING: your own IP (.$MY_OCTET) is INSIDE the spoof range ($SPOOF_LO-$SPOOF_HI)."
    echo "   Change SPOOF_LO/SPOOF_HI in this script to a range that excludes it."
    exit 1
fi

# --- warn if a REAL device already sits in the spoof range ---
echo "[*] Checking the spoof range for real devices..."
REAL=$(ip neighbor show | awk -v p="$PREFIX" -v lo="$SPOOF_LO" -v hi="$SPOOF_HI" '
    $1 ~ "^"p"\\." {
        split($1,a,"."); o=a[4];
        if (o>=lo && o<=hi && $0 ~ /lladdr/ && $0 !~ /02:00:00:00:99:99/) print $1
    }')
if [ -n "$REAL" ]; then
    echo "!! WARNING: real device(s) found inside the spoof range:"
    echo "$REAL" | sed 's/^/     /'
    echo "   They will send RST and weaken the attack."
    echo "   Move SPOOF_LO/SPOOF_HI to an empty range, or use a hotspot with only your 2 PCs."
    echo "   (continuing anyway in 3s...)"
    sleep 3
fi

echo "[1/5] Disabling firewall (ufw)..."
ufw disable >/dev/null 2>&1 || true

echo "[2/5] Disabling RX checksum offload on $IFACE..."
ethtool -K "$IFACE" rx off 2>/dev/null || echo "     (could not change offload — usually fine on Wi-Fi)"

echo "[3/5] Disabling SYN cookies + rp_filter..."
sysctl -w net.ipv4.tcp_syncookies=0 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
sysctl -w "net.ipv4.conf.$IFACE.rp_filter=0" >/dev/null 2>&1 || true

echo "[4/5] Pre-loading fake ARP entries ${PREFIX}.${SPOOF_LO}-${SPOOF_HI}..."
for i in $(seq "$SPOOF_LO" "$SPOOF_HI"); do
    ip neighbor replace "${PREFIX}.${i}" lladdr "$FAKE_MAC" dev "$IFACE" nud permanent
done
N=$(ip neighbor show dev "$IFACE" | grep -ic perm)
echo "     $N permanent ARP entries in place."

echo "[5/5] Starting victim.py on port $PORT (backlog $BACKLOG)..."
pkill -f victim.py 2>/dev/null
sleep 1
python3 victim.py "$PORT" "$BACKLOG" &
sleep 1
ss -tan | grep ":$PORT" | grep LISTEN && echo "     victim is LISTENING." || echo "     !! victim not listening — check for errors above."

if [ "$START_DASHBOARD" -eq 1 ]; then
    echo "[+] Starting dashboard on http://localhost:8080 ..."
    python3 dashboard.py "$BACKLOG" &
fi

echo ""
echo "=============================================="
echo " VICTIM READY."
echo "   Your IP for the attacker/legit_client:  $MYIP"
echo "   Tell your friend to run the attacker with prefix:  $PREFIX"
echo "   e.g.  sudo python3 attacker2.py $MYIP 80 $PREFIX 16"
echo "   Dashboard: http://localhost:8080"
echo "=============================================="