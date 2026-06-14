import subprocess

# Function to kill a process by name or PID
def kill_process(pid = None, name = None):
    try:
        if pid:
            subprocess.run(["kill", "-9", str(pid)], check = True)
            return True, f"Killed PID {pid}"

        if name:
            subprocess.run(["pkill", "-9", "-f", name], check = True)
            return True, f"Killed process {name}"

    except subprocess.CalledProcessError as e:
        return False, str(e)