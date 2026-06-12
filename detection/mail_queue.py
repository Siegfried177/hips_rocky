import subprocess
import re
from alerts.logger import register_alarm

DEFAULT_THRESHOLD = 50

# Get the size of the mail queue
def get_mail_queue_size():
    result = subprocess.run(["mailq"], capture_output=True, text=True)
    output = result.stdout

    if "empty" in output.lower(): return 0

    match = re.search(r"in (\d+) Requests", output)

    if match: return int(match.group(1))

    return 0

# Run the mail queue detection and register an alarm if the queue size exceeds the threshold
def run_mail_queue_detection(threshold=DEFAULT_THRESHOLD):
    queue_size = get_mail_queue_size()

    if queue_size >= threshold:
        register_alarm(
            alarm_type="MAIL_QUEUE_OVERFLOW",
            module="mail_queue",
            message=f"Mail queue size too high: {queue_size}",
            severity="HIGH",
            raw_data={"queue_size": queue_size}
        )