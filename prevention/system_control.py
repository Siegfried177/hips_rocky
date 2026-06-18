#!/usr/bin/env python3
import os
import shutil
import subprocess

from pathlib import Path

# Function to kill a process by name or PID
def kill_process(pid = None, name = None):
    try:
        if pid:
            subprocess.run(["kill", "-9", str(pid)], check = True, capture_output = True)
            return True, f"Proceso con PID {pid} eliminado exitosamente"

        if name:
            subprocess.run(["pkill", "-9", "-f", name], check = True, capture_output = True)
            return True, f"Ecosistema de procesos asociados a '{name}' eliminados de memoria"
        
        return False, "No se proporciono ni PID ni Nombre de proceso para mitigar la amenaza."

    except subprocess.CalledProcessError as e:
        return False, f"El proceso ya no se encontraba activo en la memoria ram: {str(e)}"

def remove_malicious_cron_entry(username, signature_keyword=""):
    try:
        cron_read = subprocess.run(["sudo", "crontab", "-u", username, "-l"], capture_output=True, text=True)
        if cron_read.returncode != 0:
            return False, None
            
        lines = cron_read.stdout.splitlines()
        new_lines = [l for l in lines if signature_keyword not in l]
        
        if len(lines) == len(new_lines):
            return False, None
            
        new_cron = "\n".join(new_lines) + "\n"
        subprocess.run(["sudo", "crontab", "-u", username, "-"], input=new_cron, text=True, check=True)
        return True, f"crontab -u {username} - [Filtro aplicado]"
    except subprocess.CalledProcessError:
        return False, None

def quarantine_or_delete_tmp_file(file_path):
    import os
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True, f"rm -f {file_path}"
        return False, None
    except Exception as e:
        print(f"[-] Error al mitigar archivo sospechoso en tmp ({file_path}): {e}")
        return False, None
    
# Handler para un archivo crítico modificado
def handle_file_tampering(file_path):
    quarantine_dir = Path("/quarantine") # Directorio seguro para archivos en cuarentena
    quarantine_dir.mkdir(exist_ok=True) # Crear el directorio si no existe

    target = quarantine_dir / Path(file_path).name

    try:
        shutil.move(file_path, target)
        return True, f"Se movio el archivo {file_path} a {target}"
    except Exception as e:
        return False, str(e)