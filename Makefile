# Compilador y flags
CC = gcc
CFLAGS = -std=gnu11 -Wall -fsanitize=address
LDFLAGS = -lpthread

# Directorios y nombres de archivos
SRC_DIR = src
BUILD_DIR = $(SRC_DIR)
SRCS_SERVER = $(SRC_DIR)/server.c
SRCS_CLIENT = $(SRC_DIR)/client.c
TARGET_SERVER = $(BUILD_DIR)/server.o
TARGET_CLIENT = $(BUILD_DIR)/client.o

# Reglas de compilación
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# Compilación del servidor
$(TARGET_SERVER): $(SRCS_SERVER)
	$(CC) $(CFLAGS) -o $(TARGET_SERVER) $(SRCS_SERVER) $(LDFLAGS)

# Compilación del cliente
$(TARGET_CLIENT): $(SRCS_CLIENT)
	$(CC) $(CFLAGS) -o $(TARGET_CLIENT) $(SRCS_CLIENT) $(LDFLAGS)

# Limpiar los binarios
clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)
