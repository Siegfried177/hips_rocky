# Guía de Instalación y Despliegue

### 0. Hardening del Servidor 

Antes de instalar las dependencias del HIPS, es fundamental reducir la superficie de ataque del sistema operativo y del motor de bases de datos utilizando los scripts provistos en la carpeta del proyecto. 

Ejecuta los scripts en el siguiente orden estricto:

**Aplicar hardening a Rocky Linux (SELinux, Firewalld, SSH sin contraseñas, etc.):**
```
chmod +x hardening/hardening_rocky.sh
sudo sh hardening/hardening_rocky.sh
```
**Aplicar hardening de configuración a PostgreSQL (Cifrado SCRAM, logs, restricción IP):**
```
chmod +x hardening/hardening_postgres.sh
sudo sh hardening/hardening_postgres.sh
```
⚠️ Nota Crítica sobre Hardening SQL: El archivo hardening.sql (que revoca permisos de creación al usuario de la base de datos) debe ser ejecutado ÚNICAMENTE DESPUÉS de haber completado el paso 4 de esta guía, ya que de lo contrario el HIPS no podrá crear sus tablas iniciales.

Sigue estos pasos en orden para clonar, configurar e instalar el HIPS de forma automatizada en tu servidor.

### 1. Clonar el Repositorio

Accede como usuario administrador o root y posiciónate en el directorio `/root`. Luego, clona el repositorio del proyecto:
```
cd /root
git clone https://github.com/Siegfried177/hips_rocky.git
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
sudo sh install.sh
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
### Troubleshooting

#### Error: Ident authentication failed

En distribuciones basadas en Red Hat, PostgreSQL viene configurado por defecto para exigir que tu usuario del sistema operativo coincida exactamente con el usuario de la base de datos (`ident`), bloqueando la conexión del archivo `.env`.

**Solución:**

1. Abre el archivo de políticas de acceso de PostgreSQL:
```
sudo nano /var/lib/pgsql/data/pg_hba.conf
```
Ve al final del archivo y localiza las líneas de conexión local. Cambia el método ident por scram-sha-256 (o md5 si fuese necesario) para que acepte contraseñas cifradas:

**Cambiar esto:**
```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
# "local" is for Unix domain socket connections only
local   all             all                                     ident
# IPv4 local connections:
host    all             all             127.0.0.1/32            ident
# IPv6 local connections:
host    all             all             ::1/128                 ident
```
**Cambiar esto:**
```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
# "local" is for Unix domain socket connections only
local   all             all                                     scram-sha-256
# IPv4 local connections:
host    all             all             127.0.0.1/32            scram-sha-256
# IPv6 local connections
host    all             all             ::1/128                 scram-sha-256
```
Guarda el archivo (Ctrl+O, Enter, Ctrl+X) y reinicia el servicio de PostgreSQL para aplicar los cambios:
```
sudo systemctl restart postgresql
```
Reinicia el demonio del HIPS:
```
sudo systemctl restart hips
```
