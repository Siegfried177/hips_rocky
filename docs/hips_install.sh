#!/bin/bash
set -e

APP_DIR="/opt/hips"
SERVICE_FILE="/etc/systemd/system/hips.service"
PYTHON_BIN="/usr/bin/python3"

DB_NAME="hips_db"
DB_USER="hips_admin"
DB_PASS="1234"

echo "[1/6] Installing dependencies..."
dnf install -y python3 python3-pip postgresql-server postgresql-contrib

echo "[2/6] Initializing PostgreSQL..."
postgresql-setup --initdb

systemctl enable postgresql
systemctl start postgresql

echo "[3/6] Creating database and user..."

sudo -u postgres psql <<EOF
CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';
CREATE DATABASE $DB_NAME OWNER $DB_USER;
EOF

echo "[4/6] Running schema..."

sudo -u postgres psql -d $DB_NAME <<EOF

CREATE TABLE alarmas (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    tipo_alarma VARCHAR(100) NOT NULL,
    ip_origen INET,
    modulo VARCHAR(100) NOT NULL,
    resuelta BOOLEAN DEFAULT FALSE,
    nivel_severidad VARCHAR(20) NOT NULL,
    usuario_affected VARCHAR(100)
);

CREATE TABLE acciones_prevencion (
    id SERIAL PRIMARY KEY,
    alarma_id INTEGER REFERENCES alarmas (id),
    accion VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    resultado VARCHAR(100),
    comando_ejecutado TEXT,
    duracion_bloqueo INTEGER
);

CREATE TABLE usuarios_web (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    rol VARCHAR(50) NOT NULL,
    ultimo_login TIMESTAMP,
    estado_cuenta VARCHAR(20),
    logins_fallidos INTEGER DEFAULT 0
);

CREATE TABLE configuracion_modulos (
    id SERIAL PRIMARY KEY,
    modulo VARCHAR(100) NOT NULL,
    parametro VARCHAR(100) NOT NULL,
    valor TEXT NOT NULL,
    activo BOOLEAN DEFAULT TRUE
);

CREATE TABLE excepciones_ip (
    id SERIAL PRIMARY KEY,
    ip_permitida INET NOT NULL,
    modulo_excluido VARCHAR(100),
    motivo TEXT,
    fecha_alta TIMESTAMP NOT NULL,
    creado_por VARCHAR(100)
);

CREATE TABLE historico_sesiones (
    id SERIAL PRIMARY KEY,
    usuario_id INTEGER REFERENCES usuarios_web (id),
    ip_conexion INET,
    user_agent TEXT,
    fecha_inicio TIMESTAMP NOT NULL,
    fecha_fin TIMESTAMP,
    token_sesion TEXT
);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT ALL ON TABLES TO $DB_USER;

EOF

echo "[5/6] Installing project..."
mkdir -p $APP_DIR
cp -r ./src/* $APP_DIR/

echo "[6/6] Creating systemd service..."

cat > $SERVICE_FILE <<EOF
[Unit]
Description=HIPS Security System
After=network.target postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=$PYTHON_BIN $APP_DIR/main.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hips
systemctl start hips

echo "HIPS installed successfully"