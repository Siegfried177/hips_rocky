import json
import os
from datetime import datetime, timezone
from alerts.email_service import send_email_to_admin
from db.repository import insert_alarm

LOG_DIR  = "/var/log/hips"
ALARM_BUFFER_FILE = os.path.join(LOG_DIR, "alarms.json")
PREVENTION_BUFFER_FILE = os.path.join(LOG_DIR, "preventions.json")

def _ensure_file():
    # Create directory if it does not exist
    os.makedirs(LOG_DIR, exist_ok=True)

    # Create file if it does not exist
    if not os.path.exists(ALARM_BUFFER_FILE):
        with open(ALARM_BUFFER_FILE, "w") as f:
            json.dump([], f) 

    if not os.path.exists(PREVENTION_BUFFER_FILE):
        with open(PREVENTION_BUFFER_FILE, "w") as f:
            json.dump([], f)  


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
    with open(ALARM_BUFFER_FILE, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []

    # Append new alarm
    data.append(alarm)

    # Save back
    with open(ALARM_BUFFER_FILE, "w") as f:
        json.dump(data, f, indent=2)

    try:
        alarm_id = insert_alarm(
            timestamp = timestamp,
            tipo_alarma = alarm_type,
            ip_origen = source_ip,
            modulo = module,
            nivel_severidad = "ALTA",
            usuario_affected = user
        )
    except Exception as e:
        print(f"[DB ERROR] {e}")
        alarm_id = None

    return alarm_id

def register_prevention_action(alarma_id, action_type, success, details=None):
    _ensure_file()

    timestamp = datetime.now(timezone.utc).isoformat()

    prevention = {
        "timestamp": timestamp,
        "alarma_id": alarma_id,
        "action_type": action_type,
        "success": success,
        "details": details or {}
    }

    # Load existing JSON
    with open(PREVENTION_BUFFER_FILE, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            data = []

    # Append new prevention action
    data.append(prevention)

    # Save back
    with open(PREVENTION_BUFFER_FILE, "w") as f:
        json.dump(data, f, indent=2)
    
    send_email_to_admin(prevention)