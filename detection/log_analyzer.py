#!/usr/bin/env python3
import re
from alerts.logger import register_alarm

def analyze_logs(file_path):
    try:
        with open(file_path, "r") as f:
            # Leemos todas las líneas del archivo de log
            lines = f.readlines()
            
            if not lines:
                return None, None
                
            # Procesamos las líneas (ponemos el foco principalmente en las últimas)
            for line in reversed(lines):
                line_lower = line.lower()
                
                # Firmas reales de SQL Injection o Ejecución Remota (Webshells)
                if (
                    "union select" in line_lower or 
                    "select" in line_lower and "from" in line_lower or
                    "union all" in line_lower or
                    "substring(" in line_lower or
                    "cmd.php" in line_lower or
                    "eval(base64" in line_lower
                ):
                    # Registramos la alarma indicando la anomalía hallada
                    alarm_id = register_alarm(
                        alarm_type = "SCANNER_HTTP",
                        module = "mod_log_analyzer",
                        message = f"Ataque Web detectado en registros: {line.strip()}",
                        source_ip = None
                    )
                    return alarm_id, "www-data"
                    
    except FileNotFoundError:
        print(f"[-] Archivo no encontrado: {file_path}")
    except Exception as e:
        print(f"[-] Error en mod_log_analyzer: {e}")
        
    return None, None
