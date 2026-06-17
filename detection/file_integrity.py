#!/usr/bin/env python3
import json, hashlib
import os
from alerts.logger import register_alarm

BASELINE_DIR = "/var/lib/hips"
BASELINE_FILE = os.path.join(BASELINE_DIR, "baseline.json")

# Calculate SHA256 hash of a file
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
    except FileNotFoundError:
        return None
    
    return sha256.hexdigest()

# Create baseline hashes for critical files
def create_baseline():
    os.makedirs(BASELINE_DIR, exist_ok = True)

    baseline = {
        "/etc/passwd": calculate_hash("/etc/passwd"),
        "/etc/shadow": calculate_hash("/etc/shadow")
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent = 4)
    print("[+] Firmas base resguardadas en el almacén seguro.")

# Check file integrity against baseline
def check_integrity():
    if not os.path.exists(BASELINE_FILE):
        return None
    
    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    for file_path, original_hash in baseline.items():
        current_hash = calculate_hash(file_path)

        if current_hash != original_hash:
            alarm_id = register_alarm(
                alarm_type = "MODIFICACION_ARCHIVO",
                module = "mod_file_integrity",
                message = f"El archivo {file_path} ha cambiado"
            )
            return alarm_id, file_path
    return None, None