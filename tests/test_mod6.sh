#!/usr/bin/env bash
echo "[*] Creando y ejecutando un proceso de prueba en /tmp..."

# Generamos un script simulado que se quede corriendo en segundo plano
cat << 'EOF' > /tmp/malicious_process
#!/usr/bin/env bash
while true; do
    sleep 1
done
EOF

chmod +x /tmp/malicious_process

# Ejecutamos en background desviando la salida
/tmp/malicious_process &
PID_FALSO=$!

echo "[+] Proceso ejecutándose en segundo plano con PID: $PID_FALSO"
echo "[*] Tu HIPS debería identificar que el ejecutable nace en /tmp y enviarle un kill -9."