#!/usr/bin/env python3
import re
from datetime import datetime, timedelta
from collections import defaultdict
from alerts.logger import register_alarm

FAILED_REGEX = re.compile(r"Failed password for (?:invalid user )?\S+ from (\d+\.\d+\.\d+\.\d+)") # Regular expression to match failed password attempts
THRESHOLD = 5 # Number of failed attempts to trigger alarm
WINDOW = timedelta(minutes = 5) # Time window to consider for failed attempts
WHITELIST = set()

# Parse secure log for failed password attempts and extract IPs and timestamps
def parse_secure_log(file_path):
    events = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                if "Failed password" in line:
                    match = FAILED_REGEX.search(line)
                    if match:
                        ip = match.group(1)
                        timestamp_str = " ".join(line.split()[:3])
                        try:
                            now = datetime.now()
                            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
                            timestamp = timestamp.replace(year = now.year)
                        except ValueError: 
                            continue
                        events.append((ip, timestamp))
    except FileNotFoundError:
        print(f"[-] Archivo no encontrado: {file_path}")

    return events

# Detect repeated failed access attempts in secure log
def detect_bruteforce(file_path):
    events = parse_secure_log(file_path)
    ip_dict = defaultdict(list)
    alerted_ips = set()
    detected_ip = None

    for ip, ts in events:
        ip_dict[ip].append(ts)

    for ip, timestamps in ip_dict.items():
        if ip in WHITELIST: 
            continue
        
        timestamps.sort()
        start = 0

        for end in range(len(timestamps)):
            while timestamps[end] - timestamps[start] > WINDOW:
                start += 1

            attempts = end - start + 1

            if attempts >= THRESHOLD and ip not in alerted_ips:
                alerted_ips.add(ip)
                
                alarm_id = register_alarm(
                    alarm_type = "ACCESO_INVALIDO_REPETIDO",
                    module = "mod_access_monitor",
                    message = f"Se detectaron {attempts} intentos de acceso fallidos desde la IP {ip}",
                    source_ip = ip
                )
                detected_ip = ip

                return alarm_id, detected_ip
    return None, None