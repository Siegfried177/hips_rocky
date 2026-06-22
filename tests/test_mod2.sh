#!/usr/bin/env bash
if [ "$EUID" -ne 0 ]; then
  echo "[-] Por favor, ejecuta como root: sudo ./test_mod2.sh"
  exit 1
fi

echo "[*] Simulando escalación de privilegios (Creando usuario con UID 0)..."
# -o permite duplicar el UID 0, -u 0 asigna el UID de root
useradd -o -u 0 -g 0 -m -s /bin/bash hacker_test

echo "[+] Usuario 'hacker_test' creado con UID 0 con éxito."
echo "[*] Revisar logs del HIPS (sudo journalctl -u hips -f). Debería detectarlo, matarle las sesiones y bloquearlo."