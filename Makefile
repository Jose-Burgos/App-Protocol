# Compilador y flags
CC = gcc
CFLAGS = -std=c11 -Wall -fsanitize=address
LDFLAGS = -lpthread

# Fuentes y ejecutables
SRCS_SERVER = src/server.c
SRCS_CLIENT = src/client.c
TARGET_SERVER = server
TARGET_CLIENT = client

# Reglas de compilación
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# Compilación del servidor
server: $(SRCS_SERVER)
	$(CC) $(CFLAGS) -o $(TARGET_SERVER) $(SRCS_SERVER) $(LDFLAGS)

# Compilación del cliente
client: $(SRCS_CLIENT)
	$(CC) $(CFLAGS) -o $(TARGET_CLIENT) $(SRCS_CLIENT) $(LDFLAGS)

# Limpiar los binarios
clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)
