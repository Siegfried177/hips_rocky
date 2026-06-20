import os
import subprocess

BLOCKLIST_PATH = "/var/lib/hips/blocked_ips.txt"

def load_blocklist():
    """Load blocked IPs from file into a set"""
    if not os.path.exists(BLOCKLIST_PATH):
        return set()

    with open(BLOCKLIST_PATH, "r") as f:
        return set(line.strip() for line in f if line.strip())


def save_to_blocklist(ip):
    """Persist a newly blocked IP"""
    os.makedirs(os.path.dirname(BLOCKLIST_PATH), exist_ok=True)

    with open(BLOCKLIST_PATH, "a") as f:
        f.write(f"{ip}\n")


# Function to block an IP using firewalld
def block_ip(ip, duration=None):
    if ip in BLOCKLIST_PATH: return True, f"EXITO: La IP {ip} ya ha sido bloqueada anteriormente"
    if not ip or ip == "N/A":
        return False, "Direccion Ip invalida o ausente. No se puede aplicar bloqueo de red."
    try:
        # Block immediate runtime
        subprocess.run(
            ["firewall-cmd", "--add-rich-rule", f'rule family="ipv4" source address="{ip}" reject'],
            check = True, capture_output = True
        )

        # Make it permanent
        subprocess.run(
            ["firewall-cmd", "--permanent", "--add-rich-rule", f'rule family="ipv4" source address="{ip}" reject'],
            check=True, capture_output=True
        )

        save_to_blocklist(ip)
        return True, f"EXITO: IP {ip} bloqueada exitosamente"

    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode().strip() if e.stderr else str(e)
        return False, f"Error de firewalld: {error_msg}"