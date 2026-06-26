#!/bin/bash

echo "=== TEST SNIFFER DETECTION START ==="

# 1. Detect interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

if [ -z "$IFACE" ]; then
    echo "No interface found"
    exit 1
fi

echo "Using interface: $IFACE"

# 2. Enable promiscuous mode (trigger PROMISC detection)
echo "[+] Enabling PROMISC mode"
sudo ip link set "$IFACE" promisc on

echo "[+] Checking PROMISC state"
ip link show "$IFACE" | grep PROMISC

# 3. Fake suspicious processes (safe simulation)
echo "[+] Launching fake blacklist processes"

# simulate tcpdump
bash -c 'exec -a tcpdump sleep 300' &
PID1=$!

# simulate wireshark
bash -c 'exec -a wireshark sleep 300' &
PID2=$!

# simulate tshark
bash -c 'exec -a tshark sleep 300' &
PID3=$!

echo "Fake PIDs:"
echo $PID1 $PID2 $PID3

echo "=== TEST COMPLETE ==="