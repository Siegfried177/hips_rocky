import json
import os
from datetime import datetime

ALERT_BUFFER_FILE = "/var/log/hips/alarms_buffer.jsonl"

def _ensure_file():
    os.makedirs(os.path.dirname(ALERT_BUFFER_FILE), exist_ok=True)
    if not os.path.exists(ALERT_BUFFER_FILE):
        with open(ALERT_BUFFER_FILE, "w") as f:
            pass

def register_alarm(alarm_type, module, message,
                    severity="INFO",
                    source_ip=None,
                    user=None,
                    raw_data=None):
    """
    Central alarm registration function (TEMPORARY STORAGE LAYER)
    """

    _ensure_file()

    alarm = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": alarm_type,
        "severity": severity,
        "module": module,
        "source_ip": source_ip,
        "user": user,
        "message": message,
        "raw_data": raw_data or {}
    }

    # Append to local file (temporary DB substitute)
    with open(ALERT_BUFFER_FILE, "a") as f:
        f.write(json.dumps(alarm) + "\n")

    return alarm