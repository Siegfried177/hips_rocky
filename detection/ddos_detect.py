#!/usr/bin/env python3
from collections import defaultdict
import os
from alerts.logger import register_alarm
from db.repository import get_config_value

DNS_LOG_PATH = "/var/log/dns.log"
BLOCKLIST_PATH = "/var/lib/hips/blocked_ips.txt"

# Function to load blocked IPs from file
def load_blocklist():
    """Load blocked IPs from file into a set"""
    if not os.path.exists(BLOCKLIST_PATH):
        return set()

    with open(BLOCKLIST_PATH, "r") as f:
        return set(line.strip() for line in f if line.strip())

# Function to persist a newly blocked IP
def save_to_blocklist(ip):
    """Persist a newly blocked IP"""
    os.makedirs(os.path.dirname(BLOCKLIST_PATH), exist_ok=True)

    with open(BLOCKLIST_PATH, "a") as f:
        f.write(f"{ip}\n")

# Function to parse the DNS log file
def parse_dns_log(file_path):
    ip_counter = defaultdict(int)

    # Create file if it does not exist
    if not os.path.exists(file_path):
        print(f"[+] Log file not found, creating: {file_path}")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        open(file_path, "w").close()

    try:
        with open(file_path, "r") as f:
            for line in f:
                parts = line.split()

                if not parts:
                    continue

                ip = parts[0]
                ip_counter[ip] += 1

    except Exception as e:
        print(f"[-] Error reading log file: {e}")

    return ip_counter

# Function to detect DDoS
def detect_ddos(file_path=DNS_LOG_PATH):
    ip_counts = parse_dns_log(file_path)
    blocked_ips = load_blocklist()

    THRESHOLD = get_config_value("DDOS_THRESHOLD")[0]

    for ip, count in ip_counts.items():

        if count > THRESHOLD and ip not in blocked_ips:

            # register alarm
            alarm_id = register_alarm(
                module="mod_ddos",
                alarm_type="DDOS_DETECTADO",
                message=f"{count} solicitudes de DNS detectadas desde {ip}",
                source_ip=ip
            )

            # persist block
            save_to_blocklist(ip)

            return alarm_id, ip

    return None, None