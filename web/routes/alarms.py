from flask import Blueprint, jsonify
from db.repository import get_all_alarms

alarms_bp = Blueprint("alarms", __name__, url_prefix="/alarms")

# GET /alarms
@alarms_bp.route("/", methods=["GET"])
def list_alarms():
    alarms = get_all_alarms()
    return jsonify({
        "count": len(alarms),
        "alarms": alarms
    })

# GET /alarms/status
@alarms_bp.route("/status", methods=["GET"])
def alarms_status():
    alarms = get_all_alarms()

    return jsonify({
        "system": "ACTIVE",
        "alarms_count": len(alarms)
    })