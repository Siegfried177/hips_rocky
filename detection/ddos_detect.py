#!/usr/bin/env python3
from collections import defaultdict
from alerts.logger import register_alarm

THRESHOLD = 100 # Number of requests from an IP to trigger alarm

def parse_dns_log(file_path):
    ip_counter = defaultdict(int)

    try:
        with open(file_path, "r") as f:
            for line in f:
                parts = line.split()

                if not parts:
                    continue

                ip = parts[0] 
                ip_counter[ip] += 1
    except FileNotFoundError:
        print(f"[-] Archivo de trazas de red no encontrado: {file_path}")

    return ip_counter


def detect_ddos(file_path):
    ip_counts = parse_dns_log(file_path)

    for ip, count in ip_counts.items():
        if count > THRESHOLD:
            alarm_id = register_alarm(
                module = "mod_ddos", 
                alarm_type = "DDOS_DETECTADO", 
                message = f"{count} solicitudes de DNS de la IP {ip} ", source_ip = ip
            )
            return alarm_id, ip
    return None, None