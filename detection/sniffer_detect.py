import subprocess
from alerts.logger import register_alarm
from db.repository import insert_prevention_action
from prevention.process_kill import kill_process_by_name

BLACKLIST_PROCESSES = [
    "tcpdump",
    "wireshark",
    "tshark",
    "dumpcap",
    "ettercap"
]

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
        register_alarm(
            alarm_type="PROMISCUOUS_MODE",
            module="sniffer_detect",
            message=f"Interface {iface} in PROMISC mode"
        )

    suspicious = get_suspicious_processes() # Check sniffing tools

    for proc in suspicious:
        register_alarm(
            alarm_type="SNIFFER_PROCESS",
            module="sniffer_detect",
            message=f"Suspicious process detected: {proc}"
        )

# Handler for a detected suspicious process 
def handle_suspicious_process(proc):
    alarm = register_alarm(
        alarm_type="SNIFFER_PROCESS",
        module="sniffer_detect",
        message=f"Suspicious process detected: {proc}"
    )

    success, result_msg = kill_process_by_name(proc) # PREVENTION ACTION

    insert_prevention_action(
        alarma_id = alarm,
        accion="KILL_PROCESS",
        resultado=result_msg,
        comando_ejecutado=f"pkill -f {proc}",
        duracion_bloqueo=None
    )