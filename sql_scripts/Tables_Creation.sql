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