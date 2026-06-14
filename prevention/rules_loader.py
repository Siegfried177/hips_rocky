import json
import os

RULES_PATH = os.path.join("config", "prevention_rules.json")

# Load prevention rules from JSON file
def load_rules():
    with open(RULES_PATH, "r") as f:
        return json.load(f)