#!/usr/bin/env python3
import os
import sys
import threading
import time
from datetime import datetime, timezone

# Capa de presentación/API
from web import app

# Capa de persistencia/logs
from db.repository import insert_prevention_action
from alerts.logger import register_alarm 

# Módulos de la carpeta detection
from detection.access_monitor import detect_bruteforce
from detection.users_monitor import detect_uid_zero_escalation
from detection.sniffer_detect import run_sniffer_detection
from detection.log_analyzer import analyze_logs
from detection.process_monitor import detect_suspicious_processes
from detection.cron_monitor import detect_malicious_cron
from detection.tmp_monitor import detect_suspicious_tmp_files
from detection.file_integrity import check_integrity
from detection.ddos_detect import detect_ddos
from detection.mail_queue import run_mail_queue_detection

# Módulos de la carpeta prevention
from prevention.user_mgmt import lock_user_account, kill_user_sessions
from prevention.system_control import kill_process, remove_malicious_cron_entry, quarantine_or_delete_tmp_file, handle_file_tampering

def system_init():
    print("[*] Iniciando Sistema HIPS...")
    
    SECURE_LOG = "/var/log/secure"
    WEB_LOG = "/var/log/httpd/access_log"
    
    while True:
        try:
            # ==========================================
            # MÓDULO 1: Integridad de Archivos 
            # ==========================================
            alarm_id, data = check_integrity()
            
            if alarm_id and data:
                print(f"[!] Alerta de Integridad detectada en el archivo {data}")

                success, command = handle_file_tampering(data)

                insert_prevention_action(
                    alarma_id = alarm_id,
                    accion = "ALERTA_INTEGRIDAD",
                    timestamp = datetime.now(timezone.utc),
                    resultado = "EXITO" if success else "FALLIDO",
                    comando_ejecutado = command,
                    duracion_bloqueo = None
                )

        except Exception as e:
            print(f"[-] Error en el bucle principal: {e}")
            
        time.sleep(10)
    

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
app = app.create_app()
print("[*] Iniciando aplicación web en http://0.0.0.0:5000")

if __name__ == "__main__":
    t = threading.Thread(target=system_init, daemon=True)
    t.start()
    
    app.run(
        host = "0.0.0.0",
        port = 5000,
        debug = False
    )
