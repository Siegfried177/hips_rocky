import smtplib
from email.mime.text import MIMEText

MAILS_SUBJECT = {
                    "sniffer_detect": "Intrusión por Captura de Paquetes Detectada",
                    "mail_queue": "Alerta de Cola de Correos",
                    "ddos_detect": "DDOS Detectado",
                    }

MAILS_BODY = {
                "sniffer_detect":"Alerta Crítica: El módulo de red detectó la ejecución ilícita de herramientas de snifffers o una mutación a modo promiscuo.\nAcción de prevención: Proceso eliminado del sistema y banderas de red restauradas de inmediato a su estado seguro.",
                "mail_queue": ""
                }

# Function to send email alerts to the admin
def send_email_to_admin(alarm):
    sender = "hips@system.local"
    receiver = "admin@company.com"
    subject = f"[HIPS ALERTA] - {MAILS_SUBJECT.get(alarm['module'])}"
    body = MAILS_BODY[alarm['module']]

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver

    try:
        with smtplib.SMTP("localhost") as server: server.send_message(msg)

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")