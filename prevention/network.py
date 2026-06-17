import subprocess

# Function to disable PROMISC mode on a given interface
def disable_promisc(interface):
    try:
        subprocess.run(
            ["ip", "link", "set", interface, "promisc", "off"],
            check = True, capture_output = True
        )

        return True, f"Modo promiscuo desactivado en interfaz {interface}"

    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode().strip() if e.stderr else str(e)
        return False, f"Error de Kernel: {error_msg}"