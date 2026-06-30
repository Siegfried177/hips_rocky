#!/bin/bash

LOG="/var/log/dns.log"

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
echo "[+] Done"