#!/usr/bin/env python3
import os
import pwd
import sys
import threading
import time
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from datetime import datetime, timezone
from pathlib import Path

# Capa de presentación/API
from prevention.engine import execute_action
from prevention.mail_handler import block_mail_ports, flush_mail_queue, stop_mail_service
from web import app

# Capa de persistencia/logs
from db.repository import insert_prevention_action, get_module_value
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

# Soporte para archivos .env
from dotenv import load_dotenv

load_dotenv()

def ensure_environment_setup():
    
    print("[*] Verificando entorno y estructura de directorios...")
    
    dirs = ["/var/log/hips", "/var/lib/hips", "/var/log/httpd", "/quarantine"]
    for d in dirs:
        try:
            Path(d).mkdir(parents=True, exist_ok=True)
            
            try:
                os.chown(d, 0, 0) 
            except PermissionError:
                print(f"[-] Advertencia: No se pudo cambiar el propietario de {d} a root:root (puede estar en una carpeta compartida o bloqueado por SELinux).")
                
            # Aplicar permisos estrictos
            if d in ["/var/lib/hips", "/quarantine"]:
                os.chmod(d, 0o700)
            elif d == "/var/log/hips":
                os.chmod(d, 0o750)
                
        except Exception as e:
            print(f"[-] Error crítico al crear el directorio {d}: {e}")

def ensure_database_setup():
    print("[*] Iniciando verificación estructurada de PostgreSQL...")
    
    # Parámetros del superusuario para la creación del entorno base
    PG_ROOT_USER = os.getenv("PG_ROOT_USER", "postgres")
    PG_ROOT_PASS = os.getenv("PG_ROOT_PASSWORD", "postgres")
    PG_HOST = os.getenv("DB_HOST", "localhost")

    # Parámetros de la aplicación HIPS extraídos del .env
    DB_NAME = os.getenv("DB_NAME", "hips_db")
    DB_USER = os.getenv("DB_USER", "hips_admin")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "1234")
    # ──────────────────────────────────────────────────

    # PASO 1: Conexión a la base 'postgres' para crear el Entorno del HIPS
    try:
        conn_init = psycopg2.connect(
            dbname="postgres", user=PG_ROOT_USER, password=PG_ROOT_PASS, host=PG_HOST
        )
        conn_init.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur_init = conn_init.cursor()

        # Verificar y crear Rol/Usuario hips_admin de forma dinámica
        cur_init.execute("SELECT 1 FROM pg_roles WHERE rolname=%s;", (DB_USER,))
        if not cur_init.fetchone():
            print(f"[+] Creando usuario administrativo '{DB_USER}'...")
            # Usamos as_string o formateo seguro para identificadores nativos en SQL
            cur_init.execute(f"CREATE USER {DB_USER} WITH PASSWORD %s;", (DB_PASSWORD,))
        else:
            print(f"[*] El usuario '{DB_USER}' ya existe en el sistema.")

        # Verificar y crear Base de Datos hips_db asignando su dueño
        cur_init.execute("SELECT 1 FROM pg_database WHERE datname=%s;", (DB_NAME,))
        if not cur_init.fetchone():
            print(f"[+] Creando base de datos '{DB_NAME}' asignada a {DB_USER}...")
            cur_init.execute(f"CREATE DATABASE {DB_NAME} OWNER {DB_USER};")
        else:
            print(f"[*] La base de datos '{DB_NAME}' ya existe.")

        cur_init.close()
        conn_init.close()

    except Exception as e:
        print(f"[-] Error crítico en la pre-configuración de Postgres: {e}")
        return

    # PASO 2: Conexión directa a la DB de la app para inyectar tus tablas nativas
    sql_script_path = Path("sql_scripts/Tables_Creation.sql")
    if not sql_script_path.exists():
        print(f"[-] Error: No se encontró el archivo Tables_Creation.sql en {sql_script_path}.")
        return

    try:
        print(f"[*] Conectando a '{DB_NAME}' para verificar la estructura de tablas...")
        conn_db = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=PG_HOST
        )
        cur_db = conn_db.cursor()

        # Leemos tu script SQL corregido
        sql_content = sql_script_path.read_text()
        
        # Ejecutamos el lote completo de tablas e inyección de privilegios
        cur_db.execute(sql_content)
        conn_db.commit()
        
        cur_db.close()
        conn_db.close()
        print("[+++] ¡Base de datos e infraestructura de tablas desplegada exitosamente! [+++]")

    except Exception as e:
        print(f"[-] Error al inyectar el esquema de tablas SQL: {e}")

def system_init():
    print("[*] Iniciando Sistema HIPS...")

    ensure_environment_setup()
    ensure_database_setup()
    
    WEB_LOG = "/var/log/httpd/access_log"
    SECURE_LOG = "/var/log/secure"

    
    while True:
        try:
            # ==========================================
            # MÓDULO 1: Integridad de Archivos 
            # ==========================================
            alarm_id, data = check_integrity() if get_module_value("file_integrity") else (None, None)
            
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
            # MÓDULO 2: Monitoreo de Usuarios (UID 0)
            # ==========================================
            alarm_id_u, username_u = detect_uid_zero_escalation() if get_module_value("users_monitor") else (None, None)
            
            if alarm_id_u and username_u:
                print(f"[!] Escalación de privilegios detectada. Usuario malicioso UID 0: {username_u}")
                kill_success, kill_cmd = kill_user_sessions(username_u)
                lock_success, lock_cmd = lock_user_account(username_u)
                success_u = kill_success and lock_success
                command_u = f"{kill_cmd} && {lock_cmd}" if success_u else "Fallo en mitigación"
                insert_prevention_action(
                    alarma_id = alarm_id_u,
                    accion = "BLOQUEO_USUARIO",
                    resultado = "EXITO" if success_u else "FALLIDO",
                    comando_ejecutado = command_u,
                    duracion_bloqueo = None
                )

            # ==========================================
            # MÓDULO 3: Detector de Sniffers
            # ==========================================
            if get_module_value("sniffer_detect"):
                run_sniffer_detection()

            # ==========================================
            # MÓDULO 4: Analizador de Logs Web
            # ==========================================
            alarm_id_l, target_l = analyze_logs(WEB_LOG) if get_module_value("log_analyzer") else (None, None)
            
            if alarm_id_l and target_l:
                print(f"[!] Ataque Web detectado (SQLi/Webshell) en {WEB_LOG}")
                success_l, command_l = kill_process(name="httpd")
                insert_prevention_action(
                    alarma_id = alarm_id_l,
                    accion = "REINICIO_SERVICIO_HTTPD",
                    resultado = "EXITO" if success_l else "FALLIDO",
                    comando_ejecutado = command_l,
                    duracion_bloqueo = None
                )
                
            # ==========================================
            # MÓDULO 5: Cola de Correos 
            # ==========================================
            alarm_id, data = run_mail_queue_detection() if get_module_value("mail_queue") else (None, None)
            
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
            # MÓDULO 6: Monitoreo de Procesos Sospechosos
            # ==========================================
            alarm_id_p, pid_p = detect_suspicious_processes() if get_module_value("process_monitor") else (None, None)
            
            if alarm_id_p and pid_p:
                print(f"[!] Proceso malicioso detectado corriendo en directorio temporal. PID: {pid_p}")
                success_p, command_p = kill_process(pid=pid_p)
                insert_prevention_action(
                    alarma_id = alarm_id_p,
                    accion = "KILL_PROCESO_TEMPORAL",
                    resultado = "EXITO" if success_p else "FALLIDO",
                    comando_ejecutado = command_p,
                    duracion_bloqueo = None
                )

            # ==========================================
            # MÓDULO 7: Monitoreo de Archivos Temporales (/tmp)
            # ==========================================
            alarm_id_t, file_path_t = detect_suspicious_tmp_files() if get_module_value("tmp_monitor") else (None, None)
            
            if alarm_id_t and file_path_t:
                print(f"[!] Archivo peligroso detectado en directorio temporal: {file_path_t}")
                success_t, command_t = quarantine_or_delete_tmp_file(file_path_t)
                insert_prevention_action(
                    alarma_id = alarm_id_t,
                    accion = "ELIMINAR_ARCHIVO_TMP",
                    resultado = "EXITO" if success_t else "FALLIDO",
                    comando_ejecutado = command_t,
                    duracion_bloqueo = None
                )
                
            # ==========================================
            # MÓDULO 8: Detector de DDOS
            # ==========================================
            alarm_id, data = detect_ddos() if get_module_value("ddos_detect") else (None, None)
            
            if alarm_id and data:
                print(f"[!] Alerta de DDOS detectada desde la IP {data}")

                execute_action("DDOS_DETECTADO", data, alarm_id)
            
            # ==========================================
            # MÓDULO 9: Monitoreo de Cron Estructurado 
            # ==========================================
            if get_module_value("cron_monitor"):
                for user in pwd.getpwall():
                    alarm_id_c, username_c = detect_malicious_cron(user.pw_name)
                    
                    if alarm_id_c and username_c:
                        print(f"[!] Persistencia maliciosa detectada en crontab del usuario: {username_c}")
                        success_c, command_c = remove_malicious_cron_entry(username_c, signature_keyword="bash")
                        insert_prevention_action(
                            alarma_id = alarm_id_c,
                            accion = "LIMPIEZA_CRON",
                            resultado = "EXITO" if success_c else "FALLIDO",
                            comando_ejecutado = command_c,
                            duracion_bloqueo = None
                        )
                    
			# ==========================================
            # MÓDULO 10: Intentos de Acceso Repetidos
            # ==========================================
            alarm_id, data = detect_bruteforce(SECURE_LOG) if get_module_value("access_monitor") else (None, None)
            
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
