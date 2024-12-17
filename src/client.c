#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9999
#define BUFFER_SIZE 1024

void send_file(int socket_fd, const char *file_path);
int authenticate(int socket_fd);

int main() {
    int socket_fd;
    struct sockaddr_in server_addr;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("ERROR: No se pudo crear el socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("ERROR: Dirección IP no válida o no soportada");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("ERROR: Fallo en la conexión con el servidor");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    printf("Conectado al servidor.\n");

    if (authenticate(socket_fd) != 0) {
        close(socket_fd);
        printf("Autenticación fallida. Cerrando conexión.\n");
        exit(EXIT_FAILURE);
    }

    const char *upload_command = "UPLOAD\n";
    if (send(socket_fd, upload_command, strlen(upload_command), 0) == -1) {
        perror("ERROR: No se pudo enviar el comando UPLOAD");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    char file_path[BUFFER_SIZE];
    printf("Ingrese la ruta del archivo a enviar: ");
    fgets(file_path, BUFFER_SIZE, stdin);
    file_path[strcspn(file_path, "\n")] = '\0';

    send_file(socket_fd, file_path);

    close(socket_fd);
    printf("Conexión cerrada.\n");

    return 0;
}

int authenticate(int socket_fd) {
    char username[BUFFER_SIZE], password[BUFFER_SIZE];

    printf("Ingrese su nombre de usuario: ");
    fgets(username, BUFFER_SIZE, stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("Ingrese su contraseña: ");
    fgets(password, BUFFER_SIZE, stdin);
    password[strcspn(password, "\n")] = '\0';

    char auth_message[BUFFER_SIZE];
    snprintf(auth_message, sizeof(auth_message), "%s %s\n", username, password);


    if (send(socket_fd, auth_message, strlen(auth_message), 0) == -1) {
        perror("ERROR: Fallo al enviar la autenticación");
        return -1;
    }

    char response[BUFFER_SIZE];
    if (recv(socket_fd, response, BUFFER_SIZE, 0) <= 0) {
        perror("ERROR: No se recibió respuesta del servidor");
        return -1;
    }

    response[strcspn(response, "\n")] = '\0';

    printf("Respuesta del servidor: '%s'\n", response);

    if (strcmp(response, "AUTH_OK\\r\\n") == 0) {
        printf("Autenticación exitosa.\n");
        return 0;
    } else {
        printf("Autenticación fallida.\n");
        return -1;
    }
}

void send_file(int socket_fd, const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("ERROR: No se pudo abrir el archivo");
        return;
    }

    struct stat file_stat;
    if (stat(file_path, &file_stat) < 0) {
        perror("ERROR: No se pudo obtener la información del archivo");
        fclose(file);
        return;
    }

    const char *file_name = strrchr(file_path, '/');
    file_name = (file_name) ? file_name + 1 : file_path;

    char file_info[BUFFER_SIZE];
    snprintf(file_info, sizeof(file_info), "%s|%ld", file_name, file_stat.st_size);

    if (send(socket_fd, file_info, strlen(file_info), 0) == -1) {
        perror("ERROR: Fallo al enviar la información del archivo");
        fclose(file);
        return;
    }

    char response[BUFFER_SIZE] = {0};

    if (recv(socket_fd, response, sizeof(response), 0) <= 0 || strcmp(response, "READY") != 0) {
        perror("ERROR: No se recibió confirmación del servidor");
        fclose(file);
        return;
    }

    printf("Enviando archivo: %s\n", file_name);

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(socket_fd, buffer, bytes_read, 0) == -1) {
            perror("ERROR: Fallo al enviar los datos del archivo");
            fclose(file);
            return;
        }
    }

    printf("Archivo enviado con éxito.\n");

    fclose(file);
}
