#!/bin/bash

echo "[*] Mail Queue HIPS Test Script"

# Step 1: Ensure postfix is running (optional toggle)
echo "[*] Restarting postfix..."
sudo systemctl restart postfix

# Step 2: Generate mail load
echo "[*] Generating fake emails..."

for i in {1..30}
do
    echo "Test message $i - $(date)" | sendmail test$i@example.com
done

echo "[*] Emails sent"

# Step 3: Show current queue
echo "[*] Current mail queue:"
mailq

echo "[*] Test complete"