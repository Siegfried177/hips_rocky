#!/usr/bin/env python3
import os
from alerts.logger import register_alarm

def detect_suspicious_tmp_files():
    target_dirs = ["/tmp", "/var/tmp"]
    dangerous_extensions = [".sh", ".py", ".pl", ".php", ".elf", ".exe"]
    
    for directory in target_dirs:
        if not os.path.exists(directory):
            continue
        try:   
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink() or not os.path.exists(entry.path):
                            continue
                        
                        if entry.is_file():
                            file_name = entry.name
                            file_path = entry.path
                            
                            has_dangerous_ext = any(file_name.lower().endswith(ext) for ext in dangerous_extensions)
                            
                            is_executable = os.access(file_path, os.X_OK)
                            
                            if has_dangerous_ext or is_executable:
                                alarm_id = register_alarm(
                                    alarm_type = "ARCHIVO_TMP_SOSPECHOSO",
                                    module = "mod_tmp_monitor",
                                    message = f"Se detectó un archivo ejecutable o script potencialmente malicioso en ruta temporal: {file_path}",
                                    source_ip = None
                                )
                                return alarm_id, file_path
                    except (FileNotFoundError, PermissionError):
                        continue
        except Exception as e:
            print(f"[-] Error en mod_tmp_monitor al escanear {directory}: {e}")
            
    return None, None