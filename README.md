# Guía de Instalación y Despliegue

Sigue estos pasos en orden para clonar, configurar e instalar el HIPS de forma automatizada en tu servidor.

### 1. Clonar el Repositorio
Accede como usuario administrador o root y posiciónate en el directorio `/root`. Luego, clona el repositorio del proyecto:

```
cd /root
git clone [https://github.com/tu_usuario/hips_rocky.git](https://github.com/tu_usuario/hips_rocky.git)
cd hips_rocky
```

### 2. Configurar las Variables de Entorno (.env)

El HIPS requiere conectarse a tu base de datos para registrar las alertas. El instalador creará un archivo .env basado en la plantilla de ejemplo.

Abre el archivo para configurar tus credenciales reales de PostgreSQL:
```
# Nota: Si el archivo .env aún no existe, el instalador lo creará por ti en el siguiente paso.
# Si prefieres crearlo antes de instalar, ejecuta: cp .env.example .env

nano .env
```
Asegúrate de rellenar los datos correspondientes a tu base de datos:
```
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=hips_db
DB_USER=hips_admin
DB_PASSWORD=TuContraseñaAquí
```
(Para guardar los cambios en nano presiona Ctrl + O, Enter y para salir Ctrl + X).
### 3. Ejecutar el Instalador Automatizado

El repositorio cuenta con un script (install.sh) que se encarga de:

- Instalar pip3 y las dependencias de Python listadas en requirements.txt.

- Crear de manera automatizada el archivo de servicio de Systemd.

- Recargar y levantar el demonio del HIPS en segundo plano.

Asigna permisos de ejecución y corre el script como root:
```
chmod +x install.sh
sudo ./install.sh
```
### 4. Reiniciar el Servicio para Aplicar la Configuración

Una vez que el instalador finalice con éxito y hayas configurado tu archivo .env con las credenciales de la base de datos, debes reiniciar el servicio para que el HIPS tome los cambios de conexión:
```
sudo systemctl restart hips
```
## Administración y Control del Servicio

El HIPS corre permanentemente de fondo como un demonio de Linux gestionado por Systemd. Puedes administrarlo con los siguientes comandos estándar:

**Ver el estado del servicio en tiempo real:**
```
 sudo systemctl status hips
```
**Detener el monitoreo:**
```
sudo systemctl stop hips
```
**Iniciar el monitoreo:**
```
 sudo systemctl start hips
```
**Auditar los logs de detección y prints del sistema (stdout):**
```
 sudo journalctl -u hips.service -f
```
