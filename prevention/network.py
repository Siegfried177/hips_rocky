import subprocess

# Function to disable PROMISC mode on a given interface
def disable_promisc(interface):
    try:
        subprocess.run(
            ["ip", "link", "set", interface, "promisc", "off"],
            check = True
        )

        return True, f"Modo promiscuo desactivado en interfaz {interface}"

    except subprocess.CalledProcessError as e:
        return False, str(e)