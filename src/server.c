#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <stdarg.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_LINE_LENGTH 100
#define END_OF_LINE "\\r\\n"
#define LOG_FILE_PATH "../src/server/logs/server.logs"

/* STATUS MACROS */
#define INVALID_LANGUAGE (-2)
#define TRUE 1
#define FALSE 0
#define SUCCESS "SUCCESS"
#define WARNING "WARNING"
#define ERROR "ERROR"
#define INFO "INFO"
#define HINT "HINT"

/* FUNCTION PROTOTYPES */
int is_us(const char *line, size_t *invalid_pos);
int valid_message(const char *line);
void log_activity(const char *format, ...);

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("ERROR: Socket creation failed");
        log_activity("(%s) Socket creation failed", ERROR);
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        perror("ERROR: Bind failed");
        log_activity("(%s) Bind failed", ERROR);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) == -1) {
        perror("ERROR: Listen failed");
        log_activity("(%s) Listen failed", ERROR);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_activity("(%s) Server started and listening on port: %d", INFO, PORT);

    if ((client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &addr_len)) == -1) {
        perror("ERROR: Accept failed");
        log_activity("(%s) Accept failed", ERROR);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_activity("(%s) Client connected", INFO);

    

    while (TRUE) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_read <= 0) {
            log_activity("(%s) Client disconnected", INFO);
            break;
        }

        char *end_pos = strstr(buffer, END_OF_LINE);
        if (!end_pos) {
            log_activity("(%s) Incomplete message received", WARNING);
            continue;
        }

        size_t message_length = end_pos - buffer;
        if (message_length > MAX_LINE_LENGTH) {
            log_activity("(%s) Message truncated to 100 characters", WARNING);
            buffer[MAX_LINE_LENGTH] = '\0';
        } else {
            buffer[message_length] = '\0';
        }

        size_t invalid_pos;
        if (!is_us(buffer, &invalid_pos)) {
            buffer[invalid_pos] = '\0';
            log_activity("(%s) Invalid character detected in message", WARNING);
        }

        if (strlen(buffer) > 0) {
            log_activity("(%s) %s", buffer, INFO);
        }
    }

    close(client_fd);
    close(server_fd);
    log_activity("(%s) Server shutdown", INFO);

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
    return strstr(line, END_OF_LINE) != NULL ? TRUE : FALSE;
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
