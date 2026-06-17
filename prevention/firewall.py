import subprocess

# Function to block an IP using firewalld
def block_ip(ip, duration=None):

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

        return True, f"IP {ip} bloqueada exitosamente"

    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode().strip() if e.stderr else str(e)
        return False, f"Error de firewalld: {error_msg}"