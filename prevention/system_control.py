#!/usr/bin/env python3
import subprocess

def terminate_process_by_pid(pid):
    try:
        subprocess.run(["sudo", "kill", "-9", str(pid)], check=True, capture_output=True)
        return True, f"kill -9 {pid}"
    except subprocess.CalledProcessError:
        return False, None

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