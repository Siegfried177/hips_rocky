#!/usr/bin/env python3
import psutil
from alerts.logger import register_alarm

# Detect running processes in suspicious paths (/tmp, /var/tmp, /dev/shm)
def detect_suspicious_processes():
    suspicious_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
    
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            exe_path = proc.info['exe']
            if exe_path and any(exe_path.startswith(d) for d in suspicious_dirs):
                pid = proc.info['pid']
                username = proc.info['username']
                
                alarm_id = register_alarm(
                    alarm_type = "PROCESO_ALTO_CONSUMO",
                    module = "mod_process_monitor",
                    message = f"Proceso sospechoso detectado corriendo desde directorio temporal. PID: {pid}, Ruta: {exe_path}",
                    source_ip = None
                )
                return alarm_id, pid
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            print(f"[-] Acceso denegado al leer detalles de un proceso.")
        except psutil.ZombieProccess:
            continue
        except Exception as e:
            print(f"[-] Error inesperado en mod_proccess_monitor: {e}")
            continue
    return None, None
