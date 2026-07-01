#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "[-] Por favor, ejecuta este script como root."
  exit 1
fi

echo "[*] Iniciando la instalación automatizada del HIPS..."

if [ ! -f .env ]; then
    echo "[*] Creando archivo de configuración .env desde la plantilla..."
    cp .env.example .env
    echo "[+] Archivo .env creado. Recuerda editarlo con tus credenciales."
else
    echo "[*] El archivo .env ya existe. Omitiendo este paso."
fi

echo "[*] Verificando e instalando pip3..."

dnf install python3-pip -y > /dev/null

echo "[*] Instalando Postfix..."
dnf install postfix -y > /dev/null

echo "[*] Habilitando e iniciando Postfix..."
systemctl enable postfix --now

if [ -f requirements.txt ]; then
    echo "[*] Instalando dependencias de Python desde requirements.txt..."
    pip3 install -r requirements.txt
    if [ $? -eq 0 ]; then
        echo "[+] Dependencias de Python instaladas con éxito."
    else
        echo "[-] Error al instalar las dependencias de Python."
        exit 1
    fi
else
    echo "[-] ERROR: No se encontró el archivo requirements.txt en la raíz."
    exit 1
fi

echo "[*] Creando el archivo de servicio /etc/systemd/system/hips.service..."

cat << 'EOF' > /etc/systemd/system/hips.service
[Unit]
Description=Host Intrusion Prevention System (HIPS) Daemon
After=network.target postgresql.service

[Service]
Type=simple
User=root
Group=root

WorkingDirectory=/root/hips_rocky

ExecStart=/usr/bin/python3 /root/hips_rocky/main.py
Restart=on-failure
RestartSec=5s

Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Recargando el gestor de servicios de Linux (systemd)..."
systemctl daemon-reload

echo "[*] Habilitando e iniciando el servicio hips.service..."
systemctl enable hips.service --now

echo ""
echo "========================================================================"
echo "[+] ¡INSTALACIÓN COMPLETADA CON ÉXITO!"
echo "========================================================================"
echo "Nota: El servicio ya está corriendo de fondo."
echo "IMPORTANTE: Abre el archivo .env ('nano .env') para configurar la"
echo "contraseña real de tu base de datos y luego reinicia el HIPS con:"
echo "'sudo systemctl restart hips'"
echo "========================================================================"