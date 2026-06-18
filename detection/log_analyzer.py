#!/usr/bin/env python3
import re
from alerts.logger import register_alarm

def analyze_logs(file_path):
    try:
        with open(file_path, "r") as f:
            for line in f:
                if "sql injection" in line.lower() or "web shell" in line.lower():
                    alarm_id = register_alarm(
                        alarm_type = "SCANNER_HTTP",
                        module = "mod_log_analyzer",
                        message = f"Ataque detectado en registros de servicios web: {line.strip()}",
                        source_ip = None
                    )
                    return alarm_id, "www-data"
    except FileNotFoundError:
        print(f"[-] Archivo no encontrado: {file_path}")
    except Exception as e:
        print(f"[-] Error en mod_log_analyzer: {e}")
        
    return None, None