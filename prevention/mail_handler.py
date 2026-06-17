import subprocess

# Mail handling functions for prevention actions related to mail queue issues
def block_mail_ports():
    ports = ["25", "465", "587"] # Common mail ports: SMTP, SMTPS, and Submission

    try:
        for port in ports:
            subprocess.run([
                "firewall-cmd", "--add-rich-rule",
                f'rule family="ipv4" port port="{port}" protocol="tcp" reject'
            ], check=True, capture_output=True)
            
        return True, "Puertos de correo (25, 465, 587) bloqueados exitosamente"
    except subprocess.CalledProcessError as e:
        return False, f"Fallo al bloquear puertos de red: {str(e)}"

# Flush the mail queue using postsuper command
def flush_mail_queue():
    try:
        subprocess.run(["postsuper", "-d", "ALL"])
        return True, "Cola de correo vaciada exitosamente"
    except subprocess.CalledProcessError as e:
        return False, f"Fallo al vaciar la cola de Postfix: {str(e)}"

# Stop the mail service using systemctl
def stop_mail_service(service_name = "postfix"):
    try:
        subprocess.run(
            ["systemctl", "stop", service_name],
            check = True, capture_output = True
        )

        return True, f"Servicio {service_name} detenido exitosamente"

    except subprocess.CalledProcessError as e:
        return False, f"Fallor al detener {service_name}: {str(e)}"