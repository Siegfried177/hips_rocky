#!/bin/bash

LOG="/tmp/dns_test.log"

echo "[+] Cleaning old log"
rm -f "$LOG"

echo "[+] Generating normal traffic..."
for i in {1..50}; do
    echo "1.1.1.1 query_$i" >> "$LOG"
done

echo "[+] Generating attack traffic (10.0.0.1)..."
for i in {1..120}; do
    echo "10.0.0.1 attack_$i" >> "$LOG"
done

echo "[+] Generating medium traffic (2.2.2.2)..."
for i in {1..80}; do
    echo "2.2.2.2 normal_$i" >> "$LOG"
done

echo "[+] Running detector..."
python3 - <<EOF
from your_module import detect_ddos

alarm_id, ip = detect_ddos("$LOG")

print("ALARM:", alarm_id)
print("BLOCKED IP:", ip)
EOF

echo "[+] Done"