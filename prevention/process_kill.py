import subprocess

# Function to kill a process by name or PID
def kill_process(pid = None, name = None):
    try:
        if pid:
            subprocess.run(["kill", "-9", str(pid)], check = True, capture_output = True)
            return True, f"Proceso con PID {pid} eliminado exitosamente"

        if name:
            subprocess.run(["pkill", "-9", "-f", name], check = True, capture_output = True)
            return True, f"Ecosistema de procesos asociados a '{name}' eliminados de memoria"
        
        return False, "No se proporciono ni PID ni Nombre de proceso para mitigar la amenaza."

    except subprocess.CalledProcessError as e:
        return False, f"El proceso ya no se encontraba activo en la memoria ram: {str(e)}"