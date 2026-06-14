import subprocess
from alerts.logger import register_alarm
from db.repository import insert_prevention_action
from prevention.engine import execute_action
from prevention.process_kill import kill_process

BLACKLIST_PROCESSES = ["tcpdump", "wireshark", "tshark", "dumpcap", "ettercap"]

# Get all interfaces in PROMISC mode
def get_interfaces_promisc():
    result = subprocess.run(["ip", "link"], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    promisc_interfaces = []

    for line in lines:
        if "PROMISC" in line:
            iface = line.split(":")[1].strip()
            promisc_interfaces.append(iface)

    return promisc_interfaces

# Check for suspicious processes related to sniffing tools
def get_suspicious_processes():
    result = subprocess.run(["ps", "aux"], capture_output = True, text = True)
    processes = result.stdout.lower()
    found = []

    for proc in BLACKLIST_PROCESSES:
        if proc in processes: found.append(proc)

    return found

# Main function to run sniffer detection checks
def run_sniffer_detection():
    promisc_ifaces = get_interfaces_promisc() # Check PROMISC mode
    for iface in promisc_ifaces:
        handle_promisc_interface(iface)

    suspicious = get_suspicious_processes() # Check sniffing tools
    for proc in suspicious:
        handle_suspicious_process(proc)

# Handler for a detected suspicious process 
def handle_suspicious_process(proc):
    alarm = register_alarm(module = "sniffer_detect", alarm_type = "SNIFFER_DETECTADO", message = f"Proceso sospechoso detectado: {proc}")

    success_bool, result_msg = execute_action(alarm_type = "SNIFFER_DETECTADO", data = {"process": proc}) # PREVENTION ACTION
    success = "EXITO" if success_bool else "FALLO"

    insert_prevention_action(
        alarma_id = alarm,
        accion = "KILL_PROCESS",
        resultado = f"{success}: {result_msg}",
        comando_ejecutado = f"pkill -f {proc}",
        duracion_bloqueo = None
    )

# Handler for a detected interface in PROMISC mode
def handle_promisc_interface(iface):
    alarm = register_alarm(module = "sniffer_detect", alarm_type = "MODO_PROMISCUO_DETECTADO", message = f"Interfaz en modo promiscuo detectada: {iface}")

    success_bool, result_msg = execute_action(alarm_type = "MODO_PROMISCUO_DETECTADO", data = {"interface": iface}) # PREVENTION ACTION
    success = "EXITO" if success_bool else "FALLO"

    insert_prevention_action(
        alarma_id = alarm,
        accion = "DISABLE_PROMISC",
        resultado = f"{success}: {result_msg}",
        comando_ejecutado = f"ip link set {iface} promisc off",
        duracion_bloqueo = None
    )