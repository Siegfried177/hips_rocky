#!/usr/bin/env python3
import os
import sys
import threading
import time
from datetime import datetime, timezone

# Capa de presentación/API
from prevention.engine import execute_action
from prevention.mail_handler import block_mail_ports, flush_mail_queue, stop_mail_service
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
                    resultado = "EXITO" if success else "FALLIDO",
                    comando_ejecutado = command,
                    duracion_bloqueo = None
                )
            
            
            # ==========================================
            # MÓDULO 3: Detector de Sniffers
            # ==========================================
            run_sniffer_detection()
    
            
            # ==========================================
            # MÓDULO 5: Cola de Correos 
            # ==========================================
            alarm_id, data = run_mail_queue_detection()
            
            if alarm_id and data:
                print(f"[!] Alerta de Cola de Correos detectada, tamaño: {data}")
                ALARM_ACTIONS =[stop_mail_service, block_mail_ports, flush_mail_queue]

                for action in ALARM_ACTIONS:
                    success, command = action()

                    if action == stop_mail_service:
                        action_upper = "STOP_MAIL_SERVICE"
                    elif action == block_mail_ports:
                        action_upper = "BLOCK_MAIL_PORTS"
                    else:
                        action_upper = "FLUSH_MAIL_QUEUE"

                    insert_prevention_action(
                        alarma_id = alarm_id,
                        accion = action_upper,
                        resultado = "EXITO" if success else "FALLIDO",
                        comando_ejecutado = command,
                        duracion_bloqueo = None
                    )


            # ==========================================
            # MÓDULO 8: Detector de DDOS
            # ==========================================
            alarm_id, data = detect_ddos()
            
            if alarm_id and data:
                print(f"[!] Alerta de DDOS detectada desde la IP {data}")

                execute_action("DDOS_DETECTADO", data, alarm_id)


# ==========================================
            # MÓDULO 10: Intentos de Acceso Repetidos
            # ==========================================
            alarm_id, data = detect_bruteforce(SECURE_LOG)
            
            if alarm_id and data:
                print(f"[!] Alerta de intentos de acceso repetidos detectada desde la IP {data}")

                execute_action(alarm_type = 'ACCESO_INVALIDO_REPETIDO', alarm_id= alarm_id,data = data)


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
