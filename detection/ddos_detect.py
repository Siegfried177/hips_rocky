from collections import defaultdict
from alerts.logger import register_alarm

THRESHOLD = 100 # Number of requests from an IP to trigger alarm

def parse_dns_log(file_path):
    ip_counter = defaultdict(int)

    with open(file_path, "r") as f:
        for line in f:
            parts = line.split()
            ip = parts[0] 
            ip_counter[ip] += 1

    return ip_counter


def detect_ddos(file_path):
    ip_counts = parse_dns_log(file_path)

    for ip, count in ip_counts.items():
        if count > THRESHOLD:
            register_alarm(module = "ddos_detect", alarm_type = "DDOS_DETECTADO", message = f"{count} de solicitudes de DNS de la IP {ip} ", source_ip = ip)