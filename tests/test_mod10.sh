#!/bin/bash

echo "[*] Simulating bruteforce over time..."

for i in {1..13}
do
    TS=$(date "+%b %d %H:%M:%S")

    echo "$TS server sshd[1000]: Failed password for fakeuser from 1.2.3.13 port 22" | sudo tee -a /var/log/secure

    echo "[+] Injected attempt $i at $TS"

    sleep 1
done