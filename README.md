# TPE: Protocolos de aplicacion
## Archivos de configuración
Contamos con 3 archivos de configuracion:

### 1. **auth.txt**
Que tiene en cada línea el nombre del usuario, la contraseña y el rol (ADMIN o USER) separados por un espacio.
**Ejemplo de `auth.txt`:**
```text
root root ADMIN
user1 password USER
```

### 2. **case.properties**
Tiene una línea por cada usuario que ejecutó alguna vez el comando "SET case ON" o "SET case OFF". 
Primero está el nombre de usuario, y separado pro un espacio un entero que indica con un 1 que es case_sensitive, y con un 0 que es case_insensitive.
```text
root=1
user=1
```
### 3. **cfg.properties** 
Es un archivo de configuración en donde se indica, el timeout, el puerto que usa el servidor por defecto y si el sistema es case_sensitive o no (lo indica mediante un 1 o un 0)
```text
port=9999
idle_timeout=60
case_sensitive=0
```

También contamos con un archivo client.c, que ejecuta un cliente para poder subir los archivos en el directorio files.
Dentro de ese directorio, se crea una carpeta para cada usuario y allí se guardan los archivos que este sube.


