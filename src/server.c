#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_LINE_LENGTH 100
#define LOG_FILE_PATH "../src/server/logs/server.logs"
#define USERS_FILE_PATH "../src/server/db/auth.txt"

/* STATUS MACROS */
#define INVALID_LANGUAGE (-2)
#define TRUE 1
#define FALSE 0
#define SUCCESS "SUCCESS"
#define WARNING "WARNING"
#define ERROR "ERROR"
#define INFO "INFO"
#define HINT "HINT"
#define DEBUG "DEBUG"

/* FUNCTION PROTOTYPES */
int is_us(const char *line, size_t *invalid_pos);
int valid_message(const char *line);
void log_activity(const char *format, ...);
int authenticate_user(const char *credentials, char *role);
void *handle_client(void *client_socket);

int main(void) {
    int server_fd;
    struct sockaddr_in server_addr;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("ERROR: Socket creation failed");
        log_activity("(%s) Socket creation failed", ERROR);
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("ERROR: Bind failed");
        log_activity("(%s) Bind failed", ERROR);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) == -1) {
        perror("ERROR: Listen failed");
        log_activity("(%s) Listen failed", ERROR);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_activity("(%s) Server started and listening on port: %d", INFO, PORT);

    while (TRUE) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

        if (client_fd == -1) {
            perror("ERROR: Accept failed");
            log_activity("(%s) Accept failed", ERROR);
            continue;
        }

        log_activity("(%s) Client connected", INFO);

        pthread_t thread_id;
        int *pclient = malloc(sizeof(int));
        if (!pclient) {
            log_activity("(%s) Memory allocation failed for client socket", ERROR);
            close(client_fd);
            continue;
        }
        *pclient = client_fd;

        if (pthread_create(&thread_id, NULL, handle_client, pclient) != 0) {
            perror("ERROR: Failed to create thread");
            log_activity("(%s) Failed to create thread", ERROR);
            free(pclient);
            close(client_fd);
            continue;
        }

        pthread_detach(thread_id);
    }

    close(server_fd);
    return 0;
}

int is_us(const char *line, size_t *invalid_pos) {
    for (size_t i = 0; line[i] != '\0'; i++) {
        if (line[i] < 0 || line[i] > 127) {
            *invalid_pos = i;
            return FALSE;
        }
    }
    *invalid_pos = strlen(line);
    return TRUE;
}

int valid_message(const char *line) {
    return strstr(line, "\r\n") != NULL ? TRUE : FALSE;
}

void log_activity(const char *format, ...) {
    FILE *log_file = fopen(LOG_FILE_PATH, "a");
    if (log_file == NULL) {
        perror("ERROR: Could not create log file");
        return;
    }

    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strcspn(timestamp, "\n")] = '\0';

    fprintf(log_file, "[%s] ", timestamp);
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);

    fprintf(log_file, "\n");
    fclose(log_file);
}

void *handle_client(void *client_socket) {
    int client_fd = *((int *)client_socket);
    free(client_socket);

    char buffer[BUFFER_SIZE];
    char role[BUFFER_SIZE] = {0};
    int authenticated = FALSE;

    log_activity("(%s) New client connection established", INFO);

    while (!authenticated) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_read <= 0) {
            log_activity("(%s) Client disconnected during authentication", INFO);
            close(client_fd);
            return NULL;
        }

        buffer[bytes_read] = '\0';

        buffer[strcspn(buffer, "\r\n")] = '\0';

        log_activity("(%s) Received credentials: %s", DEBUG, buffer);

        if (strlen(buffer) == 0) {
            const char *prompt_msg = "Please enter your credentials (username password):\r\n";
            send(client_fd, prompt_msg, strlen(prompt_msg), 0);
            continue;
        }

        if (authenticate_user(buffer, role)) {
            authenticated = TRUE;
            const char *success_msg = "Authentication successful. Welcome!\r\n";
            send(client_fd, success_msg, strlen(success_msg), 0);
            log_activity("(%s) User authenticated with role: %s", SUCCESS, role);
        } else {
            const char *error_msg = "Authentication failed. Try again.\r\n";
            send(client_fd, error_msg, strlen(error_msg), 0);
            log_activity("(%s) Authentication attempt failed", ERROR);
        }
    }

    while (authenticated) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                log_activity("(%s) Client disconnected", INFO);
            } else {
                log_activity("(%s) Error receiving data from client", ERROR);
            }
            break;
        }

        buffer[bytes_read] = '\0';

        buffer[strcspn(buffer, "\r\n")] = '\0';

        if (strlen(buffer) == 0) {
            continue;
        }

        log_activity("(%s) Received message: %s", INFO, buffer);

        if (strcmp(buffer, "logout") == 0) {
            const char *logout_msg = "Logged out. Goodbye!\r\n";
            send(client_fd, logout_msg, strlen(logout_msg), 0);
            log_activity("(%s) User logged out", INFO);
            break;
        }

        const char *response = "Message received.\r\n";
        send(client_fd, response, strlen(response), 0);
    }

    close(client_fd);
    return NULL;
}

int authenticate_user(const char *credentials, char *role) {
    if (credentials == NULL || strlen(credentials) == 0) {
        return FALSE;
    }

    char* pos = strstr(credentials, "\\r\\n");
    if (pos) {
        log_activity("(%s) Removing trailing newline character", DEBUG);
        *pos = '\0';
    }

    char user[BUFFER_SIZE / 3], pass[BUFFER_SIZE / 3];

    if (sscanf(credentials, "%s %s", user, pass) != 2) {
        log_activity("(%s) Invalid credentials format", ERROR, credentials);
        return FALSE;
    }

    log_activity("(%s) User: %s, Password: %s", DEBUG, user, pass);

    FILE *file = fopen(USERS_FILE_PATH, "r");
    if (!file) {
        log_activity("(%s) Could not open users file: %s", ERROR, USERS_FILE_PATH);
        return FALSE;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';

        char stored_user[BUFFER_SIZE / 3], stored_pass[BUFFER_SIZE / 3], stored_type[BUFFER_SIZE / 3];

        if (sscanf(line, "%s %s %s", stored_user, stored_pass, stored_type) == 3) {
            log_activity("(%s) Comparing: '%s %s' with '%s %s'", DEBUG, stored_user, stored_pass, user, pass);

            if (strcmp(stored_user, user) == 0 && strcmp(stored_pass, pass) == 0) {
                strncpy(role, stored_type, BUFFER_SIZE - 1);
                role[BUFFER_SIZE - 1] = '\0';
                fclose(file);
                return TRUE;
            }
        }
    }

    fclose(file);
    return FALSE;
}

