from db.connection import get_connection
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash

# Helper function to parse a value from string to bool or int
def parse_value(value):
    if value.isdigit():
        return int(value)

    try:
        return float(value)
    except:
        pass

    if value.lower() in ["true", "false"]:
        return value.lower() == "true"

    return value

# Function to insert a new alarm into the 'alarmas' table
def insert_alarm(timestamp, tipo_alarma, ip_origen, modulo, nivel_severidad, usuario_affected = None):
    conn = get_connection()
    cur = conn.cursor()

    query = """
        INSERT INTO alarmas (
            timestamp, tipo_alarma, ip_origen, modulo,
            nivel_severidad, usuario_affected
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id;
    """

    cur.execute(query, (
        timestamp,
        tipo_alarma,
        ip_origen,
        modulo,
        nivel_severidad,
        usuario_affected
    ))

    alarm_id = cur.fetchone()[0]

    conn.commit()
    cur.close()
    conn.close()

    return alarm_id

# Function to insert a new action into the 'acciones_prevencion' table
def insert_prevention_action(alarma_id, accion, resultado, comando_ejecutado = None, duracion_bloqueo = None):
    conn = get_connection()
    cur = conn.cursor()

    query = """
        INSERT INTO acciones_prevencion (
            alarma_id,
            accion,
            timestamp,
            resultado,
            comando_ejecutado,
            duracion_bloqueo
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id;
    """

    cur.execute(query, (
        alarma_id,
        accion,
        datetime.now(timezone.utc),
        resultado,
        comando_ejecutado,
        duracion_bloqueo
    ))

    prev_action_id = cur.fetchone()[0]
    
    conn.commit()
    cur.close()
    conn.close()
    
    return prev_action_id

# Function to retrieve all alarms
def get_all_alarms(limit = 100):
    conn = get_connection()
    cur = conn.cursor()

    query = """
        SELECT id, timestamp, tipo_alarma, ip_origen, modulo, nivel_severidad, usuario_affected
        FROM alarmas
        ORDER BY timestamp DESC
        LIMIT %s;
    """

    cur.execute(query, (limit,))
    rows = cur.fetchall()

    cur.close()
    conn.close()

    alarms = []
    for row in rows:
        alarms.append({
            "id": row[0],
            "timestamp": row[1],
            "type": row[2],
            "ip": row[3],
            "module": row[4],
            "severity": row[5],
            "user": row[6]
        })

    return alarms

# Function to retrieve configuration parameters for a given module
def get_module_config(module):
    conn = get_connection()
    cur = conn.cursor()

    query = """
        SELECT parametro, valor, activo
        FROM configuracion_modulos
        WHERE modulo = %s
    """

    cur.execute(query, (module,))
    rows = cur.fetchall()

    cur.close()
    conn.close()

    config = []

    for parametro, valor, activo in rows:
        config.append({
            "parametro": parametro,
            "valor": parse_value(valor),
            "activo": activo
        })

    return config

# Function to update the value of a configuration parameter
def update_module_config(module, parameter, value, active):
    conn = get_connection()
    cur = conn.cursor()

    query = """
        UPDATE configuracion_modulos
        SET valor = %s, activo = %s
        WHERE modulo = %s AND parametro = %s;
    """

    cur.execute(query, (value, active, module, parameter))
    conn.commit()

    cur.close()
    conn.close()

    return True

# Function to retrieve a user by username from the 'usuarios_web' table
def get_user_by_username(username):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, username, password_hash, rol, estado_cuenta, logins_fallidos
        FROM usuarios_web
        WHERE username = %s
    """, (username,))

    return cur.fetchone()

# Function to create a new user in the 'usuarios_web' table
def create_user(username, password, rol="user"):
    conn = get_connection()
    cur = conn.cursor()

    password_hash = generate_password_hash(password)

    cur.execute("""
        INSERT INTO usuarios_web (username, password_hash, rol, estado_cuenta)
        VALUES (%s, %s, %s, %s)
    """, (username, password_hash, rol, "active"))
    
    conn.commit()
    cur.close()
    conn.close()

# Function to verify user credentials
def verify_user(username, password):
    user = get_user_by_username(username)

    if not user:
        return None

    stored_hash = user[2]

    if check_password_hash(stored_hash, password):
        return user

    return None

# Function to retrieve all users
def get_all_users():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, username, rol FROM usuarios_web")
    users = cur.fetchall()

    cur.close()
    conn.close()

    return users

# Function to retrieve a user by ID
def get_user_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, username, rol FROM usuarios_web WHERE id = %s",
        (user_id,)
    )

    user = cur.fetchone()

    cur.close()
    conn.close()

    return user

# Function to update a user
def update_user(user_id, username, role):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE usuarios_web
        SET username = %s, rol = %s
        WHERE id = %s
        AND role != 'admin'
    """, (username, role, user_id))

    conn.commit()

    cur.close()
    conn.close()

# Function to delete a user
def delete_user(user_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM usuarios_web
        WHERE id = %s
        AND rol != 'admin'
    """, (user_id,))

    conn.commit()

    cur.close()
    conn.close()
    
    # Function to retrieve a configuration value by parameter and active flag

# Function to retrieve configuration value and active flag by parameter
def get_config_value(parametro):
    conn = get_connection()
    cur = conn.cursor()

    query = """
        SELECT valor, activo
        FROM configuracion_modulos
        WHERE parametro = %s
        LIMIT 1;
    """

    cur.execute(query, (parametro))
    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return None

    valor, activo_db = row

    return parse_value(valor), activo_db


def get_module_value(modulo):
    conn = get_connection()
    cur = conn.cursor()

    query = """
        SELECT activo
        FROM configuracion_modulos
        WHERE modulo = %s
        AND parametro = 'activo'
        LIMIT 1;
    """

    cur.execute(query, (modulo))
    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return None

    activo_db = row

    return parse_value(activo_db)