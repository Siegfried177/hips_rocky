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
#from detection.users_monitor import detect_uid_zero_escalation
from detection.sniffer_detect import run_sniffer_detection
from detection.log_analyzer import analyze_logs
#from detection.process_monitor import detect_suspicious_processes
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
            # MÓDULO 3: Detector de Sniffers
            # ==========================================
            alarm_id, data = run_sniffer_detection()

            # ==========================================
            # MÓDULO 4: Analizador de Logs Web
            # ==========================================
            alarm_id_log, usuario_web = analyze_logs(WEB_LOG)
            
            if alarm_id_log:
                print(f"[!] Alerta de Exploit Web detectada en logs.")
                # Acciones reactivas correspondientes...

            # ==========================================
            # MÓDULO 5: Cola de Correos 
            # ==========================================
            alarm_id, data = run_mail_queue_detection()
            
            if alarm_id and data:
                print(f"[!] Alerta de Cola de Correos detectada, tamaño: {data}")

                success, command = handle_file_tampering(data)

                insert_prevention_action(
                    alarma_id = alarm_id,
                    accion = "ALERTA_COLA_CORREOS",
                    timestamp = datetime.now(timezone.utc),
                    resultado = "EXITO" if success else "FALLIDO",
                    comando_ejecutado = command,
                    duracion_bloqueo = None
                )

            # ==========================================
            # MÓDULO 6: Procesos Sospechosos
            # ==========================================
            alarm_id_proc, pid_malicioso = detect_suspicious_processes()
            
            if alarm_id_proc and pid_malicioso:
                print(f"[!] Proceso sospechoso corriendo en /tmp. PID: {pid_malicioso}")
                
                exito, comando = kill_process(pid_malicioso)
                
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
            # MÓDULO 8: Detector de DDOS
            # ==========================================
            alarm_id, data = detect_ddos()
            
            if alarm_id and data:
                print(f"[!] Alerta de DDOS detectada desde la IP {data}")

                success, command = handle_file_tampering(data)

                insert_prevention_action(
                    alarma_id = alarm_id,
                    accion = "ALERTA_DDOS",
                    timestamp = datetime.now(timezone.utc),
                    resultado = "EXITO" if success else "FALLIDO",
                    comando_ejecutado = command,
                    duracion_bloqueo = None
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
                
            # ==========================================
            # MÓDULO 10: Intentos de Acceso Repetidos
            # ==========================================
            alarm_id, data = detect_bruteforce()
            
            if alarm_id and data:
                print(f"[!] Alerta de intentos de acceso repetidos detectada desde la IP {data}")

                success, command = handle_file_tampering(data)

                insert_prevention_action(
                    alarma_id = alarm_id,
                    accion = "ALERTA_BRUTEFORCE",
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
        debug = True
    )