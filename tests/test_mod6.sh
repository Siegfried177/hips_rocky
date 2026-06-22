#!/usr/bin/env bash

# ==============================================================================
# SCRIPT DE PRUEBA: MÓDULO 6 - DETECCIÓN DE PROCESOS EN RUTAS TEMPORALES
# Usa el intérprete de Python clonado en /tmp para forzar la detección del binario
# ==============================================================================

echo "[*] Iniciando entorno de simulación para el Módulo 6..."

TARGET_DIR="/tmp"
MALICIOUS_BIN="malware_falso_test"
TARGET_PATH="${TARGET_DIR}/${MALICIOUS_BIN}"

# 1. Copiar el binario de Python a /tmp con el nombre del "malware"
# Esto engaña a psutil para que proc.info['exe'] devuelva exactamente la ruta de /tmp
echo "[*] Clonando entorno de ejecución de Python en ${TARGET_PATH}..."
cp /usr/bin/python3 "$TARGET_PATH"
chmod +x "$TARGET_PATH"

# 2. Lanzar el proceso simulado en segundo plano
# Le pasamos un comando en línea (-c) para que se quede durmiendo en un bucle infinito
echo "[*] Ejecutando el proceso sospechoso en segundo plano..."
"$TARGET_PATH" -c "
import time;
while True: 
    time.sleep(1)
" &

FAKE_PID=$!

echo "[+] Proceso lanzado con éxito. PID: ${FAKE_PID} | Ruta: ${TARGET_PATH}"
echo "[*] Esperando 4 segundos para que el bucle del HIPS realice la captura..."
sleep 4

# 3. Verificar si el HIPS detectó y mató el proceso (Mitigación Activa)
if ps -p $FAKE_PID > /dev/null; then
    echo "[-] El proceso sospechoso sigue vivo. Validando logs..."
    echo "[*] Forzando detención manual para limpiar el entorno..."
    kill -9 $FAKE_PID 2>/dev/null
else
    echo "[+] ¡ÉXITO! El proceso sospechoso fue neutralizado (Killed) por el sistema de mitigación del HIPS."
fi

# 4. Limpieza del ejecutable de prueba en /tmp
rm -f "$TARGET_PATH"
