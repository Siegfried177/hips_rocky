CREATE TABLE IF NOT EXISTS alarmas (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    tipo_alarma VARCHAR(100) NOT NULL,
    ip_origen INET,
    modulo VARCHAR(100) NOT NULL,
    resuelta BOOLEAN DEFAULT FALSE,
    nivel_severidad VARCHAR(20) NOT NULL,
    usuario_affected VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS acciones_prevencion (
    id SERIAL PRIMARY KEY,
    alarma_id INTEGER REFERENCES alarmas (id),
    accion VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    resultado VARCHAR(100),
    comando_ejecutado TEXT,
    duracion_bloqueo INTEGER
);

CREATE TABLE IF NOT EXISTS usuarios_web (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    rol VARCHAR(50) NOT NULL,
    ultimo_login TIMESTAMP,
    estado_cuenta VARCHAR(20),
    logins_fallidos INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS configuracion_modulos (
    id SERIAL PRIMARY KEY,
    modulo VARCHAR(100) NOT NULL,
    parametro VARCHAR(100) NOT NULL,
    valor TEXT NOT NULL,
    activo BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS excepciones_ip (
    id SERIAL PRIMARY KEY,
    ip_permitida INET NOT NULL,
    modulo_excluido VARCHAR(100),
    motivo TEXT,
    fecha_alta TIMESTAMP NOT NULL,
    creado_por VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS historico_sesiones (
    id SERIAL PRIMARY KEY,
    usuario_id INTEGER REFERENCES usuarios_web (id),
    ip_conexion INET,
    user_agent TEXT,
    fecha_inicio TIMESTAMP NOT NULL,
    fecha_fin TIMESTAMP,
    token_sesion TEXT
);


INSERT INTO configuracion_modulos (id, modulo, parametro, valor, activo) VALUES
(1,  'process_monitor',   'activo', '1', TRUE),
(2,  'tmp_monitor',       'activo', '1', TRUE),
(3,  'cron_monitor',      'activo', '1', TRUE),
(4,  'file_integrity',    'activo', '1', TRUE),
(5,  'sniffer_detect',    'activo', '1', TRUE),
(6,  'users_monitor',     'activo', '1', TRUE),
(7,  'access_monitor',    'activo', '1', TRUE),
(8,  'log_analyzer',      'activo', '1', TRUE),
(9,  'mail_queue',        'activo', '1', TRUE),
(10, 'ddos_detect',       'activo', '1', TRUE),
(11, 'access_monitor',    'ACCESS_THRESHOLD', '10', TRUE),
(12, 'mail_queue',        'MAIL_QUEUE_THRESHOLD', '10', TRUE),
(13, 'access_monitor',    'ACCESS_WINDOW', '10', TRUE);


GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO hips_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO hips_admin;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TABLES TO hips_admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO hips_admin;
