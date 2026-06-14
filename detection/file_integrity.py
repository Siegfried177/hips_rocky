import json, hashlib

from alerts.logger import register_alarm

BASELINE_FILE = "baseline.json"

# Calculate SHA256 hash of a file
def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()

# Create baseline hashes for critical files
def create_baseline():
    baseline = {
        "/etc/passwd": calculate_hash("/etc/passwd"),
        "/etc/shadow": calculate_hash("/etc/shadow")
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

# Check file integrity against baseline
def check_integrity():
    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    for file_path, original_hash in baseline.items():
        current_hash = calculate_hash(file_path)

        if current_hash != original_hash:
            register_alarm(
                alarm_type = "MODIFICACION_ARCHIVO",
                module = "file_integrity",
                message = f"File modified: {file_path}"
            )