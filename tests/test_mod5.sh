#!/bin/bash

echo "[*] Mail Queue HIPS Test Script"

echo "[*] Forcing Postfix to accumulate queue..."

# Force queue accumulation and disable bounce collapsing

sudo postconf -e "default_transport = smtp"
sudo postconf -e "relayhost = [127.0.0.1]:9999"   # non-existent SMTP
sudo postconf -e "soft_bounce = yes"
sudo postfix reload

echo "[*] Generating emails..."

for i in $(seq 1 30)
do
sendmail -t <<EOF
From: [test@example.com](mailto:test@example.com)
To: user${i}@nonexistent-domain-hips.local
Subject: Test $i

This is test message $i
EOF
done

echo "[*] Emails sent"

echo "[*] Current mail queue:"
mailq

echo "[*] Restoring postfix config..."

sudo postconf -X relayhost
sudo postconf -e "soft_bounce = no"
sudo postfix reload

echo "[*] Test complete"
