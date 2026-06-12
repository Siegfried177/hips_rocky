from db.connection import get_connection

# Function to insert a new alarm into the database 'alarmas' table
def insert_alarm(timestamp, tipo_alarma, ip_origen, modulo, nivel_severidad, usuario_affected=None):
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

# Function to retrieve active configuration parameters for a given module
def get_module_config(modulo):
    conn = get_connection()
    cur = conn.cursor()

    query = """
    SELECT parametro, valor
    FROM configuracion_modulos
    WHERE modulo = %s AND activo = TRUE;
    """

    cur.execute(query, (modulo,))
    rows = cur.fetchall()

    cur.close()
    conn.close()

    return {param: value for param, value in rows}