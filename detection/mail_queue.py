#!/usr/bin/env python3
import subprocess
import re
from alerts.logger import register_alarm
from db.repository import get_config_value

# Get the size of the mail queue
def get_mail_queue_size():
    result = subprocess.run(["mailq"], capture_output = True, text = True)
    output = result.stdout

    if "empty" in output.lower(): return 0

    match = re.search(r"in (\d+) Requests", output)

    if match: return int(match.group(1))

    return 0

# Run the mail queue detection and register an alarm if the queue size exceeds the threshold
def run_mail_queue_detection():
    queue_size = get_mail_queue_size()
    
    THRESHOLD = get_config_value("MAIL_QUEUE_THRESHOLD")[0]

    if queue_size >= THRESHOLD:
        print(f"[!] Alerta: Cola de correo saturada con {queue_size} mensajes.")
        alarm_id = register_alarm(
            alarm_type="MAIL_QUEUE_ALTA",
            module="mod_mail_queue",
            message=f"Cola de correo saturada con {queue_size} mensajes.",
            raw_data={"queue_size": queue_size}
        )
        return alarm_id, queue_size
    
    return None, None