import subprocess

# Mail handling functions for prevention actions related to mail queue issues
def block_mail_ports():
    ports = ["25", "465", "587"] # Common mail ports: SMTP, SMTPS, and Submission

    for port in ports:
        subprocess.run([
            "firewall-cmd",
            "--add-rich-rule",
            f'rule family="ipv4" port port="{port}" protocol="tcp" reject'
        ])

    return True, "Puertos de correo bloqueados exitosamente"

# Flush the mail queue using postsuper command
def flush_mail_queue():
    subprocess.run(["postsuper", "-d", "ALL"])
    return True, "Cola de correo vaciada exitosamente"

# Stop the mail service using systemctl
def stop_mail_service(service_name="postfix"):
    try:
        subprocess.run(
            ["systemctl", "stop", service_name],
            check = True
        )

        return True, f"{service_name} detenido exitosamente"

    except subprocess.CalledProcessError as e:
        return False, f"Fallor al detener {service_name}: {str(e)}"