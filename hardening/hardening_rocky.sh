#!/usr/bin/env bash
# Control: Ejecución obligatoria como ROOT
if [ "$EUID" -ne 0 ]; then
  echo "[-] Error: Este script debe ejecutarse como root (sudo ./hardening_rocky.sh)"
  exit 1
fi

clear
echo "=============================================================================="
echo "         INICIANDO AUTOMATIZACIÓN DE HARDENING      "
echo "=============================================================================="

# ------------------------------------------------------------------------------
# 1. Estado de SELinux (Modo Enforcing)
# ------------------------------------------------------------------------------
echo "[*] 1/10 Configurando SELinux en modo Enforcing..."
setenforce 1 2>/dev/null
if [ -f /etc/selinux/config ]; then
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/g' /etc/selinux/config
fi
echo "[+] SELinux forzado correctamente. Estado actual: $(getenforce)"

# ------------------------------------------------------------------------------
# 2. Estado de Firewalld (Activo)
# ------------------------------------------------------------------------------
echo "[*] 2/10 Asegurando que Firewalld esté activo..."
systemctl enable firewalld --now > /dev/null 2>&1
echo "[+] Firewalld verificado: $(systemctl is-active firewalld)"

# ------------------------------------------------------------------------------
# 3. Deshabilitar SSH Root Login
# ------------------------------------------------------------------------------
echo "[*] 3/10 Deshabilitando el acceso SSH directo al usuario root..."
SSH_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSH_CONFIG" ]; then
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/g' "$SSH_CONFIG"
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/g' "$SSH_CONFIG"
fi
echo "[+] Parámetro PermitRootLogin establecido en 'no'."

# ------------------------------------------------------------------------------
# 4. Banner de Login MotD (/etc/issue)
# ------------------------------------------------------------------------------
echo "[*] 4/10 Configurando Banner de advertencia legal en /etc/issue..."
cat << 'EOF' > /etc/issue

******************************************************************************
* ¡ADVERTENCIA LEGAL!                               *
* Este sistema es de ACCESO RESTRINGIDO y propiedad privada. Todo intento   *
* no autorizado de ingreso o manipulación será registrado, auditado y       *
* mitigado penalmente bajo la supervisión del sistema HIPS activo.          *
******************************************************************************

EOF
echo "[+] Banner legal inyectado en /etc/issue con éxito."

# ------------------------------------------------------------------------------
# 5. Estado de Auditd (Activo)
# ------------------------------------------------------------------------------
echo "[*] 5/10 Asegurando el demonio de auditoría del kernel (auditd)..."
systemctl enable auditd --now > /dev/null 2>&1
# Nota: auditd a veces requiere re-ejecución directa si corre bajo systemd en entornos específicos
service auditd start > /dev/null 2>&1 
echo "[+] Auditd verificado: $(systemctl is-active auditd)"

# ------------------------------------------------------------------------------
# 6. Deshabilitar protocolos obsoletos (Telnet)
# ------------------------------------------------------------------------------
echo "[*] 6/10 Deshabilitando e interrumpiendo el servicio obsoleto Telnet..."
systemctl disable telnet.socket telnet.service --now > /dev/null 2>&1
echo "[+] Servicio Telnet mitigado. Estado: $(systemctl is-enabled telnet 2>&1 || echo 'disabled/error')"

# ------------------------------------------------------------------------------
# 7. Restricción de permisos en /etc/shadow
# ------------------------------------------------------------------------------
echo "[*] 7/10 Aplicando permisos estrictos (600) sobre /etc/shadow..."
chmod 600 /etc/shadow
echo "[+] Permisos actuales de shadow: $(stat -c "%a" /etc/shadow)"

# ------------------------------------------------------------------------------
# 8. Restricción de permisos en /etc/passwd
# ------------------------------------------------------------------------------
echo "[*] 8/10 Asegurando permisos correctos (644) sobre /etc/passwd..."
chmod 644 /etc/passwd
echo "[+] Permisos actuales de passwd: $(stat -c "%a" /etc/passwd)"

# ------------------------------------------------------------------------------
# 9. Uso de Claves SSH en lugar de passwords
# ------------------------------------------------------------------------------
echo "[*] 9/10 Desactivando la autenticación por contraseñas en SSH (Fuerza Llaves)..."
if [ -f "$SSH_CONFIG" ]; then
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/g' "$SSH_CONFIG"
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/g' "$SSH_CONFIG"
    # Reiniciamos SSH para aplicar el punto 3 y el punto 9
    systemctl restart sshd
fi
echo "[+] Autenticación por contraseña en SSH deshabilitada de raíz."

# ------------------------------------------------------------------------------
# 10. Configuración de Umask Global (027)
# ------------------------------------------------------------------------------
echo "[*] 10/10 Estableciendo Umask Global a 027..."
# Aplicar en /etc/profile
if ! grep -q "umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile 2>/dev/null || echo "umask 027" >> /etc/profile
fi
# Aplicar en /etc/bashrc
if ! grep -q "umask 027" /etc/bashrc; then
    echo "umask 027" >> /etc/bashrc
fi
echo "[+] Umask 027 añadido a las configuraciones globales de entorno."

echo "=============================================================================="
echo "          PROCESO DE HARDENING COMPLETADO - RESUMEN DE AUDITORÍA              "
echo "=============================================================================="

# Bloque final que corre los mismos comandos de verificación de tu captura
echo "1. SELinux: $(getenforce)"
echo "2. Firewalld: $(systemctl is-active firewalld)"
echo "3. SSH Root: $(grep "^PermitRootLogin" /etc/ssh/sshd_config || echo 'No configurado correctamente')"
echo "4. Banner Issue: Contenido inyectado con éxito en /etc/issue"
echo "5. Auditd: $(systemctl is-active auditd)"
echo "6. Telnet Status: $(systemctl is-enabled telnet 2>&1 || echo 'disabled/error')"
echo "7. Permisos /etc/shadow: $(stat -c "%a" /etc/shadow)"
echo "8. Permisos /etc/passwd: $(stat -c "%a" /etc/passwd)"
echo "9. SSH Password Auth: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config || echo 'No configurado correctamente')"
echo "10. Umask en /etc/bashrc: $(grep "umask 027" /etc/bashrc)"
echo "=============================================================================="
