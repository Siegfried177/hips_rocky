import subprocess

# Function to block an IP using firewalld
def block_ip(ip, duration=None):
    try:
        # Block immediate runtime
        subprocess.run(
            ["firewall-cmd", "--add-rich-rule", f'rule family="ipv4" source address="{ip}" reject'],
            check = True
        )

        # Make it permanent
        subprocess.run(
            ["firewall-cmd", "--runtime-to-permanent"],
            check = True
        )

        return True, f"IP {ip} bloqueada exitosamente"

    except subprocess.CalledProcessError as e:
        return False, str(e)