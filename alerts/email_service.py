import smtplib
from email.mime.text import MIMEText

MAILS_SUBJECT = {
"ARCHIVO_MODIFICADO_EN_CUARENTENA": "Alerta Crítica: Integridad del Sistema Comprometida",
"KILL_PROCESS": "Alerta de Seguridad: Sesión Sospechosa Detectada",
"BLOCK_IP": "Alerta Crítica: Captura de Paquetes Detectada",
"DISABLE_PROMISC": "Advertencia: Actividad Sospechosa en Logs",
"STOP_MAIL_SERVICE": "Advertencia: Anomalía en Cola de Correos",
"BLOCK_MAIL_PORTS": "Advertencia: Anomalía en Cola de Correos",
"FLUSH_MAIL_QUEUE": "Advertencia: Anomalía en Cola de Correos",
}

MAILS_BODY = {
"ARCHIVO_MODIFICADO_EN_CUARENTENA": "Se detectaron modificaciones no autorizadas en archivos críticos del sistema.\nAcción: Verificar y restaurar integridad.",
"KILL_PROCESS": "Se detectó una sesión desde origen u horario inusual.\nAcción: Revisar y, si corresponde, finalizar la sesión.",
"BLOCK_IP": "Acción: Se ha bloqueado una IP sospechosa.",
"DISABLE_PROMISC": "Se identificó una interfaz en modo promiscuo.\nAcción: Interfaz desactivada.",
"STOP_MAIL_SERVICE": "Acción: Se ha detenido el servicio de correo.",
"BLOCK_MAIL_PORTS": "Acción: Se han bloqueado los puertos de correo.",
"FLUSH_MAIL_QUEUE": "Acción: Se ha vaciado la cola de correo.",
}

# Function to send email alerts to the admin
def send_email_to_admin(prevention):
    sender = "hips@system.local"
    receiver = "admin@localhost"
    subject = f"[PREVENCIÓN AUTOMÁTICA DE SEGURIDAD REALIZADA] - {MAILS_SUBJECT.get(prevention['action_type'])}"
    body = MAILS_BODY[prevention['action_type']]

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver

    try:
        with smtplib.SMTP("localhost") as server: server.send_message(msg)

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")