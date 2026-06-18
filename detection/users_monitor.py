#!/usr/bin/env python3
import pwd
from alerts.logger import register_alarm

# Detect unauthorized users whit UID 0 (root)
def detect_uid_zero_escalation():
    try:
        for user in pwd.getpwall():
            if user.pw_uid == 0 and user.pw_name != 'root':
                username = user.pw_name
                
                alarm_id = register_alarm(
                    alarm_type = "USUARIO_SOSPECHOSO",
                    module = "mod_users_monitor",
                    message = f"Se detectó un usuario no autorizado con privilegios de root (UID 0): {username}",
                    source_ip = None
                )
                return alarm_id, username
    except Exception as e:
        print(f"[-] Error en mod_users_monitor: {e}")
        
    return None, None