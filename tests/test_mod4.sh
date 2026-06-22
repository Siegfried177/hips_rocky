#!/usr/bin/env bash
if [ "$EUID" -ne 0 ]; then
  echo "[-] Por favor, ejecuta como root: sudo ./test_mod4.sh"
  exit 1
fi

LOG_PATH="/var/log/httpd/access_log"
mkdir -p /var/log/httpd
touch "$LOG_PATH"

echo "[*] Inyectando payload malicioso de SQL Injection en los logs web..."
echo "192.168.1.50 - - [$(date +'%d/%b/%Y:%H:%M:%S %z')] \"GET /products.php?id=1' UNION SELECT NULL,username,password FROM users-- HTTP/1.1\" 200 4502" >> "$LOG_PATH"

echo "[+] Entrada maliciosa inyectada en $LOG_PATH"
echo "[*] El módulo de logs debería procesar la línea y tumbar el servicio httpd para mitigar el riesgo."