from functools import wraps
from flask import Flask, app, render_template, request, redirect, session, url_for
from db.repository import get_all_alarms, get_module_config, update_module_config, verify_user
from web.routes.alarms import alarms_bp

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

# Create the Flask application
def create_app():
    app = Flask(__name__)

    app.secret_key = "your_secret_key"
    
    app.register_blueprint(alarms_bp)
    
    # Login Page
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            user = verify_user(username, password)

            if user:
                session["user_id"] = user[0]
                session["username"] = user[1]
                session["role"] = user[3]

                return redirect("/")

            return render_template("login.html", error="Invalid credentials")

        return render_template("login.html")
    
    @app.route("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect("/login")
    
    # Main Dashboard Page
    @app.route("/")
    @login_required
    def index():
        alarms = get_all_alarms()
        status = {
            "system": "ACTIVE",
            "alarms_count": len(alarms)
        }
        return render_template("index.html", alarms=alarms, status=status)

    # Configuration Page
    @app.route("/config", methods=["GET", "POST"])
    @login_required
    def config():

        MODULES = {
            "process_monitor": "Monitor de Procesos",
            "tmp_monitor": "Monitor de Archivos Temporales",
            "cron_monitor": "Monitor de Cron",
            "file_integrity": "Monitor de Integridad de Archivos",
            "sniffer_detect": "Detección de Network Sniffer",
            "users_monitor": "Monitor de Actividad de Usuarios",
            "access_monitor": "Monitor de Control de Acceso",
            "log_analyzer": "Analyzer de Logs",
            "mail_queue": "Monitor de Cola de Correos",
            "ddos_detect": "Detección de Ataques DDoS"
        }

        # POST: update module configs
        if request.method == "POST":
            for module in MODULES.keys():
                module_config = get_module_config(module)

                for item in module_config:
                    parametro = item["parametro"]

                    value_key = f"value_{module}_{parametro}"
                    active_key = f"active_{module}_{parametro}"

                    valor = request.form.get(value_key)
                    activo = active_key in request.form

                    update_module_config(
                        module=module,
                        parameter=parametro,
                        value=valor,
                        active=activo
                    )

            return redirect("/config")

        # GET: load all module configs
        config_data = {}

        for module in MODULES.keys():
            config_data[module] = get_module_config(module)

        return render_template(
            "config.html",
            config=config_data,
            modules=MODULES
        )

    return app