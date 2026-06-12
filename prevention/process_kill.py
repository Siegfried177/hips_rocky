import subprocess

# Kill all processes matching a given name
def kill_process_by_name(process_name):
    try:
        subprocess.run(["pkill", "-f", process_name], check = True)
        
        return True, f"Process {process_name} killed"

    except subprocess.CalledProcessError:
        return False, f"Failed to kill {process_name}"