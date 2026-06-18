#!/usr/bin/env python3
import subprocess
from alerts.logger import register_alarm

def detect_malicious_cron(username):
    dangerous_keywords = ["nc ", "bash -i", "sh -i", "reverse_shell", "chmod +x"]
    
    try:
        result = subprocess.run(["sudo", "crontab", "-u", username, "-l"], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if any(keyword in line for keyword in dangerous_keywords):
                    
                    alarm_id = register_alarm(
                        alarm_type = "CRON_SOSPECHOSO",
                        module = "mod_cron_monitor",
                        message = f"Línea persistente maliciosa detectada en crontab del usuario {username}: {line.strip()}",
                        source_ip = None
                    )
                    return alarm_id, username
    except Exception as e:
        print(f"[-] Error en mod_cron_monitor: {e}")
        
    return None, None