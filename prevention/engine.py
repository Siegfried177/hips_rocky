from prevention import mail_handler
from prevention.rules_loader import load_rules
from prevention.firewall import block_ip
from prevention.process_kill import kill_process
from prevention.network import disable_promisc
from db.repository import insert_prevention_action

ACTION_MAP = {
    "BLOCK_IP": lambda data: block_ip(data.get("ip")),
    "KILL_PROCESS": lambda data: kill_process(name = data.get("process")),
    "DISABLE_PROMISC": lambda data: disable_promisc(data.get("interface")),
    "BLOCK_MAIL_TRAFFIC": lambda data: mail_handler.block_mail_ports(),
    "FLUSH_MAIL_QUEUE": lambda data: mail_handler.flush_mail_queue(),
    "STOP_MAIL_SERVICE": lambda data: mail_handler.stop_mail_service()
}

COMMAND_DESC_MAP = {
    "BLOCK_IP": lambda data: f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={data.get('ip')} reject'",
    "KILL_PROCESS": lambda data: f"pkill -9 -f {data.get('process')}",
    "DISABLE_PROMISC": lambda data: f"ip link set {data.get('interface')} promisc off",
    "BLOCK_MAIL_TRAFFIC": lambda data: "firewall-cmd --add-rich-rule (Puertos 25, 465, 587)",
    "FLUSH_MAIL_QUEUE": lambda data: "postsuper -d ALL",
    "STOP_MAIL_SERVICE": lambda data: "systemctl stop postfix"
}

# Central IPS prevention engine that executes actions based on alarm types
def execute_action(alarm_type, data, alarm_id = None):
    rules = load_rules()

    actions = rules.get(alarm_type, [])

    if not actions: 
        return False, "No hay acciones definidas para este tipo de alarma"

    results = []

    for action in actions:
        action_func = ACTION_MAP.get(action)

        if not action_func:
            result_msg = f"No se pudo encontrar la acción: {action}"
            results.append((False, result_msg))
            continue

        success, msg = action_func(data)

        desc_func = COMMAND_DESC_MAP.get(action, lambda d: "Comando Desconocido")
        comando_real = desc_func(data)

        insert_prevention_action(
            alarma_id = alarm_id,
            accion = action,
            resultado = msg,
            comando_ejecutado = comando_real,
            duracion_bloqueo = 0
        )

        results.append((success, msg))

    all_success = all(r[0] for r in results if r)

    return all_success, results