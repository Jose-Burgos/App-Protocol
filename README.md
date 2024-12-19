# TPE: Protocolos de aplicacion

Este proyecto incluye un servidor y un cliente que pueden ejecutarse localmente o utilizando Docker. A continuación, se explica cómo compilar, ejecutar y probar ambas aplicaciones.

---

## Requisitos Previos

1. **Compilador C**: Asegúrate de tener instalado un compilador compatible, como GCC.
2. **Make**: Asegúrate de tener instalado `make` para compilar los binarios.
3. **Docker** (opcional): Para ejecutar los servicios en contenedores.
4. **Docker Compose**: Para gestionar múltiples contenedores.

---

## Compilación y Ejecución Local

### Compilación

Para compilar el servidor y el cliente, utiliza el comando:

```bash
make all
```

Este comando genera los ejecutables `server.o` y `client.o` dentro del directorio `src/`.

### Ejecución

- Para iniciar el servidor:
  ```bash
  ./src/server.o
  ```

- Para ejecutar el cliente:
  ```bash
  ./src/client.o <host> <puerto> <archivo_de_comandos>
  ```

Si el archivo de comandos está vacío, el cliente te pedirá que ingreses los comandos manualmente.

La lista de comandos debe guardarse bajo el directorio test/commands

---

## Ejecución con Docker

### Paso 1: Dar Permisos al Script de Docker

Asigna permisos de ejecución al script `docker.sh`:

```bash
chmod +x docker.sh
```

### Paso 2: Ejecutar Docker Compose

Ejecuta el script `docker.sh` para iniciar el servidor y el cliente en contenedores:

```bash
./docker.sh
```

Esto utiliza Docker Compose para iniciar los servicios.

### Paso 3: Probar el Cliente

Asigna permisos de ejecución al script `client.sh`:

```bash
chmod +x client.sh
```

Ejecuta el script para conectarte a uno de los servidores:

```bash
./client.sh
```

Este script intentará conectarse a cada servidor y ejecutar una lista de comandos predefinidos. Si el archivo de comandos está vacío, el cliente pedirá que ingreses los comandos manualmente.

---

## Archivos de Comandos

El cliente requiere un archivo de comandos para ejecutar operaciones automáticamente. Ejemplo de un archivo de comandos (`commands_list.txt`):

```
GET test.txt \r\n
LIST FILES \r\n
EXIT \r\n
```

Si el archivo está vacío, el cliente solicitará los comandos manualmente.

---

## Comandos Útiles

- Compilar todo:
  ```bash
  make all
  ```

- Limpiar los binarios generados:
  ```bash
  make clean
  ```

- Ejecutar el servidor:
  ```bash
  ./src/server.o
  ```

- Ejecutar el cliente:
  ```bash
  ./src/client.o <host> <puerto> <archivo_de_comandos>
  ```


