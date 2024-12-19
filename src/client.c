#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024

int authenticate(int socket_fd);
void send_command(int socket_fd, const char *command);
int read_commands_from_file(const char *file_path, char commands[][BUFFER_SIZE], int max_commands);
void send_file(int socket_fd, const char *file_path);

int main(const int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port> <command_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_ip = argv[1];
    const int server_port = atoi(argv[2]);
    const char *command_file = argv[3];

    if (server_port <= 0 || server_port > 65535) {
        fprintf(stderr, "ERROR: Invalid port number\n");
        exit(EXIT_FAILURE);
    }

    int socket_fd;
    struct sockaddr_in server_addr;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("ERROR: Failed to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("ERROR: Invalid or unsupported IP address");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("ERROR: Connection to the server failed");
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    const char *dir_path = "./test/commands/";
    char file_path[BUFFER_SIZE];
    snprintf(file_path, sizeof(file_path), "%s%s", dir_path, command_file);
    printf("File path: %s\n", file_path);

    char commands[100][BUFFER_SIZE];
    const int num_commands = read_commands_from_file(file_path, commands, 100);

    if (num_commands == 0) {
        while (1) {
            printf("Enter command: ");
            if (fgets(commands[0], BUFFER_SIZE, stdin) == NULL) {
                break;
            }

            commands[0][strcspn(commands[0], "\n")] = '\0';
            if (commands[0][0] == '\0') {
                continue;
            }

            if (strncmp(commands[0], "UPLOAD", 6) == 0) {
                char file_path[BUFFER_SIZE];
                if (sscanf(commands[0], "UPLOAD %s", file_path) == 1) {
                    send_file(socket_fd, file_path);
                } else {
                    fprintf(stderr, "ERROR: Invalid UPLOAD command format: %s\n", commands[0]);
                }
            } else {
                send_command(socket_fd, commands[0]);
            }
        }
    } else {
        for (int i = 0; i < num_commands; i++) {
            if (strncmp(commands[i], "UPLOAD", 6) == 0) {
                char file_path[BUFFER_SIZE];
                if (sscanf(commands[i], "UPLOAD %s", file_path) == 1) {
                    send_file(socket_fd, file_path);
                } else {
                    fprintf(stderr, "ERROR: Invalid UPLOAD command format: %s\n", commands[i]);
                }
            } else {
                send_command(socket_fd, commands[i]);
            }
        }
    }

    close(socket_fd);
    return 0;
}

void send_command(int socket_fd, const char *command) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_sent, bytes_received;
    int found_crlf = 0;

    bytes_sent = send(socket_fd, command, strlen(command), 0);
    if (bytes_sent < 0) {
        perror("ERROR: Failed to send command");
        return;
    }

    printf("Server response:\n");
    while (!found_crlf) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(socket_fd, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_received < 0) {
            perror("ERROR: Failed to receive server response");
            return;
        } else if (bytes_received == 0) {
            fprintf(stderr, "ERROR: Connection closed by server\n");
            return;
        }

        buffer[bytes_received] = '\0';

        printf("%s", buffer);

        if (strstr(buffer, "\r\n")) {
            found_crlf = 1;
        }
    }

    printf("\n");
}


int read_commands_from_file(const char *file_path, char commands[][BUFFER_SIZE], const int max_commands) {
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        printf("ERROR: Could not open the file\n");
        return 0;
    }

    int num_commands = 0;
    while (fgets(commands[num_commands], BUFFER_SIZE, file) != NULL) {
        if (commands[num_commands][0] == '\0' || commands[num_commands][0] == '#') {
            continue;
        }

        num_commands++;

        if (num_commands >= max_commands) {
            break;
        }
    }

    fclose(file);
    return num_commands;
}


void send_file(const int socket_fd, const char *file_path) {
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

    fclose(file);
}