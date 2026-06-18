#!/usr/bin/env python3
import os
from alerts.logger import register_alarm

def detect_suspicious_tmp_files():
    target_dirs = ["/tmp", "/var/tmp"]
    dangerous_extensions = [".sh", ".py", ".pl", ".php", ".elf", ".exe"]
    
    for directory in target_dirs:
        try:
            if not os.path.exists(directory):
                continue
                
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    has_dangerous_ext = any(file.lower().endswith(ext) for ext in dangerous_extensions)
                    
                    is_executable = os.access(file_path, os.X_OK) and not os.path.isdir(file_path)
                    
                    if has_dangerous_ext or is_executable:
                        alarm_id = register_alarm(
                            alarm_type = "ARCHIVO_TMP_SOSPECHOSO",
                            module = "mod_tmp_monitor",
                            message = f"Se detectó un archivo ejecutable o script potencialmente malicioso en ruta temporal: {file_path}",
                            source_ip = None
                        )
                        return alarm_id, file_path
        except Exception as e:
            print(f"[-] Error en mod_tmp_monitor al escanear {directory}: {e}")
            
    return None, None