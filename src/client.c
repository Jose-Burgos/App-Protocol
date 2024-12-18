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
        perror("ERROR: Failed to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("ERROR: Invalid or unsupported IP address");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("ERROR: Connection to the server failed");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    printf("Connected to the server.\n");

    if (authenticate(socket_fd) != 0) {
        close(socket_fd);
        printf("Authentication failed. Closing connection.\n");
        exit(EXIT_FAILURE);
    }

    char file_path[BUFFER_SIZE];
    printf("Enter the path of the file to send: ");
    fgets(file_path, BUFFER_SIZE, stdin);
    file_path[strcspn(file_path, "\n")] = '\0';

    send_file(socket_fd, file_path);

    close(socket_fd);
    printf("Connection closed.\n");

    return 0;
}

int authenticate(int socket_fd) {
    char auth_message[BUFFER_SIZE];

    printf("Enter your credentials (username password): ");
    if (!fgets(auth_message, BUFFER_SIZE, stdin)) {
        fprintf(stderr, "ERROR: Failed to read credentials.\n");
        return -1;
    }

    auth_message[strcspn(auth_message, "\n")] = '\0';
    strncat(auth_message, "\r\n", BUFFER_SIZE - strlen(auth_message) - 1);

    if (send(socket_fd, auth_message, strlen(auth_message), 0) == -1) {
        perror("ERROR: Failed to send authentication message");
        return -1;
    }

    char response[BUFFER_SIZE];
    if (recv(socket_fd, response, BUFFER_SIZE, 0) <= 0) {
        perror("ERROR: No response from server");
        return -1;
    }

    response[strcspn(response, "\n")] = '\0';

    printf("Server response: '%s'\n", response);

    if (strcmp(response, "AUTH_OK\\r\\n") == 0) {
        printf("Authentication successful.\n");
        return 0;
    } else {
        printf("Authentication failed.\n");
        return -1;
    }
}

void send_file(int socket_fd, const char *file_path) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("ERROR: Could not open the file");
        return;
    }

    struct stat file_stat;
    if (stat(file_path, &file_stat) < 0) {
        perror("ERROR: Could not retrieve file information");
        fclose(file);
        return;
    }

    const char *file_name = strrchr(file_path, '/');
    file_name = (file_name) ? file_name + 1 : file_path;

    char upload_command[BUFFER_SIZE];
    snprintf(upload_command, sizeof(upload_command), "UPLOAD %s|%ld\r\n", file_name, file_stat.st_size);

    if (send(socket_fd, upload_command, strlen(upload_command), 0) == -1) {
        perror("ERROR: Failed to send upload command");
        fclose(file);
        return;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(socket_fd, buffer, bytes_read, 0) == -1) {
            perror("ERROR: Failed to send file data");
            fclose(file);
            return;
        }
    }

    printf("File '%s' sent successfully.\n", file_name);
    fclose(file);
}