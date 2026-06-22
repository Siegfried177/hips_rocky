#!/usr/bin/env bash
echo "[*] Colocando artefacto/script sospechoso en la carpeta temporal /tmp..."

TARGET_FILE="/tmp/reverse_shell.sh"

echo "#!/bin/bash" > "$TARGET_FILE"
echo "echo 'Simulación de amenaza'" >> "$TARGET_FILE"

# Le damos permisos de ejecución obligatorios para que salte la condición os.X_OK
chmod +x "$TARGET_FILE"

echo "[+] Archivo ejecutable de prueba creado en: $TARGET_FILE"
echo "[*] El monitor de /tmp del HIPS debería borrar este archivo en su próxima iteración."