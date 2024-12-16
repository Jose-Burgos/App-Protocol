#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>
#include <dirent.h>

#define BUFFER_SIZE 1024
#define MAX_LINE_LENGTH 100
#define LOG_FILE_PATH "../src/server/logs/server.logs"
#define USERS_FILE_PATH "../src/server/db/auth.txt"
#define CONFIG_FILE_PATH "../src/server/cfg.properties"
#define FILES_DIRECTORY_PATH "../src/server/db"
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

/* STRUCTS */
typedef struct {
    int client_fd;
    time_t last_activity_time;
} client_info_t;

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

/* FUNCTION PROTOTYPES */
int read_port_from_config();
int read_idle_timeout_from_config();
int is_us(const char *line, size_t *invalid_pos);
int valid_message(const char *line);
void log_activity(const char *format, ...);
int authenticate_user(const char *credentials, char *role);
void *handle_client(void *client_socket);
void parse_command(int client_fd, const char* input, const char* role);
void handle_auth(int client_fd, const char* username, const char* password);
void handle_list_files(int client_fd);
void handle_echo(int client_fd, const char* text);
void handle_get(int client_fd, const char* filename);

int main(void) {
    int server_fd;
    struct sockaddr_in server_addr;

    int port = read_port_from_config();
    if (port == -1) {
        fprintf(stderr, "ERROR: Could not read the port from config file\n");
        exit(EXIT_FAILURE);
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("ERROR: Socket creation failed");
        log_activity("(%s) Socket creation failed", ERROR);
        exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
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

    log_activity("(%s) Server started and listening on port: %d", INFO, port);

    while (TRUE) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &addr_len);

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
    pthread_rwlock_destroy(&rwlock);
    close(server_fd);
    return 0;
}

int read_port_from_config() {
    FILE *file = fopen(CONFIG_FILE_PATH, "r");
    if (file == NULL) {
        perror("ERROR: Could not open config file");
        return -1;
    }

    char line[BUFFER_SIZE];
    int port = -1;

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "port=", 5) == 0) {
            if (sscanf(line + 5, "%d", &port) != 1) {
                fprintf(stderr, "ERROR: Invalid port value in config file\n");
                fclose(file);
                return -1;
            }
            break;
        }
    }

    fclose(file);
    return port;
}

int read_idle_timeout_from_config() {
    FILE *file = fopen(CONFIG_FILE_PATH, "r");
    if (file == NULL) {
        perror("ERROR: Could not open config file");
        return -1;
    }

    char line[BUFFER_SIZE];
    int idle_timeout = -1;

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "idle_timeout=", 13) == 0) {
            if (sscanf(line + 13, "%d", &idle_timeout) != 1) {
                fprintf(stderr, "ERROR: Invalid idle timeout value in config file\n");
                fclose(file);
                return -1;
            }
            break;
        }
    }

    fclose(file);
    return idle_timeout;
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
    time_t last_activity_time = time(NULL);

    log_activity("(%s) New client connection established", INFO);

    while (!authenticated) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

        if (time(NULL) - last_activity_time > read_idle_timeout_from_config()) {
            log_activity("(%s) Client idle timeout reached. Closing connection.", INFO);
            close(client_fd);
            return NULL;
        }

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

        last_activity_time = time(NULL);
    }

    while (authenticated) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

        if (time(NULL) - last_activity_time > read_idle_timeout_from_config()) {
            log_activity("(%s) Client idle timeout reached. Closing connection.", INFO);
            break;
        }

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

        parse_command(client_fd,buffer,role);

        if (strcmp(buffer, "logout") == 0) {
            const char *logout_msg = "Logged out. Goodbye!\r\n";
            send(client_fd, logout_msg, strlen(logout_msg), 0);
            log_activity("(%s) User logged out", INFO);
            break;
        }

        const char *response = "Message received.\r\n";
        send(client_fd, response, strlen(response), 0);

        last_activity_time = time(NULL);
    }

    close(client_fd);
    return NULL;
}


int authenticate_user(const char *credentials, char *role) {
    if (credentials == NULL || strlen(credentials) == 0) {
        return FALSE;
    }

    char *pos = strstr(credentials, "\\r\\n");
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

void parse_command(int client_fd, const char* input,const char* role){
    char buffer[BUFFER_SIZE];
    strncpy(buffer, input, BUFFER_SIZE - 1);

    char* command = strtok(buffer, " ");

    if (command == NULL) {
        log_activity("(%s) Comando vacío",ERROR);
        return;
    }

    if (strcmp(command, "AUTH") == 0) {
        if (strcmp(role,"ADMIN") != 0){
            log_activity("(%s) Usted no es un usuario ADMIN",ERROR);
        }
        else{
            char* username = strtok(NULL, " ");
            char* password = strtok(NULL, "\r\n");

            if (username && password) {
                handle_auth(client_fd,username, password);
            } else {
                log_activity("(%s) AUTH requiere un username y password",ERROR);
            }
        }
    } else if (strcmp(command, "LIST") == 0) {
        char* subcommand = strtok(NULL, "\r\n");

        if (subcommand && strcmp(subcommand, "FILES") == 0) {
            handle_list_files(client_fd);
        } else {
            log_activity("(%s) LIST FILES es el único subcomando válido",ERROR);
        }
    } else if (strcmp(command, "ECHO") == 0) {
        char* text = strtok(NULL, "\r\n");

        if (text) {
            handle_echo(client_fd,text);
        } else {
            log_activity("(%s) ECHO requiere texto",ERROR);
        }
    } else if (strcmp(command, "GET") == 0) {
        char* filename = strtok(NULL, "\r\n");

        if (filename) {
            handle_get(client_fd,filename);
        } else {
            log_activity("(%s) GET requiere un nombre de archivo",ERROR);
        }
    } else {
        log_activity("(%s) Comando no reconocido",ERROR);
    }
}

void handle_auth(int client_fd,const char* username, const char* password) {

    pthread_rwlock_wrlock(&rwlock);

    FILE* file = fopen(USERS_FILE_PATH, "a");
    if (!file) {
        perror("ERROR: Could not open users file for writing");
        log_activity("(%s) Could not open users file for writing", ERROR);
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    char new_line[100];
    //TODO: Now only USER role can be created, also need to create ADMIN´s ?
    snprintf(new_line, sizeof(new_line), "%s %s USER\n", username, password);

    if (fprintf(file, "%s", new_line) < 0) {
        perror("ERROR: Could not write to users file");
        log_activity("(%s) Could not write to users file", ERROR);
    } else {
        log_activity("New user added successfully: %s\n", username);
        log_activity("(%s) New user added: %s", SUCCESS, username);
        char * message = "User added successfully \n";
        send(client_fd,message, strlen(message),0);
    }
    fclose(file);
    pthread_rwlock_unlock(&rwlock);
}

void handle_list_files(int client_fd){
    pthread_rwlock_rdlock(&rwlock);

    DIR* directory = opendir(FILES_DIRECTORY_PATH);
    if (!directory) {
        perror("ERROR: Could not open files directory");
        log_activity("(%s) Could not open files directory", ERROR);
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    struct dirent* entry;

    while ((entry = readdir(directory)) != NULL) {
        // Ignorar directorios "." y ".."
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char * message = strcat(entry->d_name,"\n");
            send(client_fd,message, strlen(message),0);
        }
    }

    closedir(directory);
    pthread_rwlock_unlock(&rwlock);
}

void handle_echo(int client_fd, const char* text){
    char * message = strcat(text,"\n");
    send(client_fd,message, strlen(message),0);
}
void handle_get(int client_fd, const char* filename){

    pthread_rwlock_rdlock(&rwlock);

    char buff[BUFFER_SIZE] = FILES_DIRECTORY_PATH;
    char* path = strcat(strcat(buff,"/"),filename);
    FILE* file = fopen(path,"r");
    if (!file) {
        log_activity("(%s) Could not open (%s) file for reading", ERROR,filename);
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char size[MAX_LINE_LENGTH];
    sprintf(size, "%ld", file_size);

    char aux[50] = "OK ";

    char * message = strcat(strcat(aux,size),"\r\n");
    send(client_fd, message, strlen(message),0);

    char line[BUFFER_SIZE];

    while(fgets(line,sizeof(line),file)){
        send(client_fd,line, strlen(line),0);
    }

    fclose(file);
    pthread_rwlock_unlock(&rwlock);
}

