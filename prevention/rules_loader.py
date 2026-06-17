import json
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_PATH = os.path.join("config", "prevention_rules.json")

# Load prevention rules from JSON file
def load_rules():
    try:
        with open(RULES_PATH, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[-] Error Critico: No se encontro el archivo de politicas en: {RULES_PATH}")
        return {}