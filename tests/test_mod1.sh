#!/bin/bash

echo "[*] File Integrity Test"

FILE="/home/test"

echo "[*] Writing to $FILE"

# Create file if it doesn't exist
touch "$FILE"

# Modify file to trigger hash change
echo "TEST_MODIFICATION_$(date)" >> "$FILE"

echo "[+] File modified successfully"

# Show content
echo "[*] Current file content:"
cat "$FILE"