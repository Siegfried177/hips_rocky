#!/usr/bin/env python3
import os
import sys
import threading
import time
from datetime import datetime, timezone

# Capa de presentación/API
from web import app

# Capa de persistencia/logs
from db.repository import create_user, insert_prevention_action
from alerts.logger import register_alarm 

# Módulos de la carpeta detection
from detection.access_monitor import detect_bruteforce
########from detection.users_monitor import detect_uid_zero_escalation
from detection.log_analyzer import analyze_logs
########from detection.process_monitor import detect_suspicious_processes
from detection.cron_monitor import detect_malicious_cron
from detection.tmp_monitor import detect_suspicious_tmp_files

# Módulos de la carpeta prevention
from prevention.user_mgmt import lock_user_account, kill_user_sessions
from prevention.system_control import terminate_process_by_pid, remove_malicious_cron_entry, quarantine_or_delete_tmp_file

def system_init():
    print("[*] Iniciando Sistema HIPS...")
    
    SECURE_LOG = "/var/log/secure"
    WEB_LOG = "/var/log/httpd/access_log"
    
    while True:
        try:

            # ==========================================
            # MÓDULO 2: Escalada de Privilegios
            # ==========================================
            alarm_id_user, username_escalated = detect_uid_zero_escalation()
            if alarm_id_user and username_escalated:
                print(f"[!] Alerta de Escalada detectada para: {username_escalated}")
                
                exito, comando = lock_user_account(username_escalated)
                kill_user_sessions(username_escalated)
                
                insert_prevention_action(
                    alarma_id=alarm_id_user,
                    accion="LOCK_AND_KILL",
                    timestamp=datetime.now(timezone.utc),
                    resultado="EXITO" if exito else "FALLIDO",
                    comando_ejecutado=comando,
                    duracion_bloqueo=None
                )

            # ==========================================
            # MÓDULO 4: Analizador de Logs Web
            # ==========================================
            alarm_id_log, usuario_web = analyze_logs(WEB_LOG)
            if alarm_id_log:
                print(f"[!] Alerta de Exploit Web detectada en logs.")
                # Acciones reactivas correspondientes...

            # ==========================================
            # MÓDULO 6: Procesos Sospechosos
            # ==========================================
            alarm_id_proc, pid_malicioso = detect_suspicious_processes()
            if alarm_id_proc and pid_malicioso:
                print(f"[!] Proceso sospechoso corriendo en /tmp. PID: {pid_malicioso}")
                
                exito, comando = terminate_process_by_pid(pid_malicioso)
                
                insert_prevention_action(
                    alarma_id=alarm_id_proc,
                    accion="TERMINATE_PROCESS",
                    timestamp=datetime.now(timezone.utc),
                    resultado="EXITO" if exito else "FALLIDO",
                    comando_ejecutado=comando,
                    duracion_bloqueo=None
                )
            # ==========================================
            # MÓDULO 7: Monitoreo de /tmp
            # ==========================================
            alarm_id_tmp, path_malicioso = detect_suspicious_tmp_files()
            if alarm_id_tmp and path_malicioso:
                print(f"[!] Archivo peligroso detectado en zona temporal: {path_malicioso}")
        
                exito, comando = quarantine_or_delete_tmp_file(path_malicioso)
            
                insert_prevention_action(
                    alarma_id=alarm_id_tmp,
                    accion="QUARANTINE_DELETE",
                    timestamp=datetime.now(timezone.utc),
                    resultado="EXITO" if exito else "FALLIDO",
                    comando_ejecutado=comando,
                    duracion_bloqueo=None
                )

            # ==========================================
            # MÓDULO 9: Persistencia en Cron
            # ==========================================
            alarm_id_cron, user_cron = detect_malicious_cron("apache")
            if alarm_id_cron and user_cron:
                print(f"[!] Persistencia detectada en el crontab de: {user_cron}")
                
                exito, comando = remove_malicious_cron_entry(user_cron, signature_keyword="reverse_shell")
                
                insert_prevention_action(
                    alarma_id=alarm_id_cron,
                    accion="CLEAN_CRON",
                    timestamp=datetime.now(timezone.utc),
                    resultado="EXITO" if exito else "FALLIDO",
                    comando_ejecutado=comando,
                    duracion_bloqueo=None
                )

        except Exception as e:
            print(f"[-] Error en el bucle principal: {e}")
            
        time.sleep(10)
        
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
app = app.create_app()
print("[*] Iniciando aplicación web en http://0.0.0.0:5000")

if __name__ == "__main__":   
    # Iniciar el hilo del sistema HIPS
    t = threading.Thread(target=system_init, daemon=True)
    t.start()
    
    # Iniciar la aplicación web
    app.run(
        host = "0.0.0.0",
        port = 5000,
        debug = True
    )