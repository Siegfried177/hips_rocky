import json
import os
from datetime import datetime, timezone

from db.repository import insert_alarm

ALERT_BUFFER_DIR  = "/var/log/hips"
ALERT_BUFFER_FILE = os.path.join(ALERT_BUFFER_DIR, "alarms_buffer.json")

def _ensure_file():
    # Create directory if it does not exist
    os.makedirs(ALERT_BUFFER_DIR, exist_ok=True)

    # Create file if it does not exist
    if not os.path.exists(ALERT_BUFFER_FILE):
        with open(ALERT_BUFFER_FILE, "w") as f:
            json.dump([], f)  # initialize as empty JSON array


def register_alarm(module, alarm_type, message, source_ip=None, user=None, raw_data=None):
    _ensure_file()

    timestamp = datetime.now(timezone.utc).isoformat()

    alarm = {
        "timestamp": timestamp,
        "type": alarm_type,
        "module": module,
        "source_ip": source_ip,
        "user": user,
        "message": message,
        "raw_data": raw_data or {}
    }

    # Load existing JSON
    with open(ALERT_BUFFER_FILE, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []

    # Append new alarm
    data.append(alarm)

    # Save back
    with open(ALERT_BUFFER_FILE, "w") as f:
        json.dump(data, f, indent=2)

    try:
        alarm_id = insert_alarm(
            timestamp=timestamp,
            tipo_alarma=alarm_type,
            ip_origen=source_ip,
            modulo=module,
            nivel_severidad="ALTA",
            usuario_affected=user
        )
    except Exception as e:
        print(f"[DB ERROR] {e}")
        alarm_id = None

    return alarm_id