#!/usr/bin/env python3
import subprocess

# Mail handling functions for prevention actions related to mail queue issues
def block_mail_ports():
    ports = ["25", "465", "587"]  # SMTP, SMTPS, Submission

    try:
        commands_executed = []

        for port in ports:
            cmd = [
                "firewall-cmd",
                "--permanent",
                "--add-rich-rule",
                f'rule family="ipv4" port port="{port}" protocol="tcp" reject'
            ]

            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True
            )

            commands_executed.append(" ".join(cmd))

        # Apply changes
        reload_cmd = ["firewall-cmd", "--reload"]

        subprocess.run(
            reload_cmd,
            check=True,
            capture_output=True,
            text=True
        )

        commands_executed.append(" ".join(reload_cmd))

        return True, commands_executed

    except subprocess.CalledProcessError as e:
        return False, e.cmd if hasattr(e, "cmd") else str(e)


def flush_mail_queue():
    try:
        cmd = ["postsuper", "-d", "ALL"]

        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )

        return True, " ".join(cmd)

    except subprocess.CalledProcessError as e:
        return False, e.cmd if hasattr(e, "cmd") else str(e)


def stop_mail_service(service_name="postfix"):
    try:
        cmd = ["systemctl", "stop", service_name]

        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )

        return True, " ".join(cmd)

    except subprocess.CalledProcessError as e:
        return False, e.cmd if hasattr(e, "cmd") else str(e)