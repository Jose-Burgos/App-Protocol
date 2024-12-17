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
#include <sys/stat.h>
#include <sys/file.h>

#define BUFFER_SIZE 1024
#define MAX_LINE_LENGTH 100
#define LOG_FILE_PATH "../src/server/logs/server.logs"
#define USERS_FILE_PATH "../src/server/db/auth.txt"
#define CASE_FILE_PATH "../src/server/case.properties"
#define CONFIG_FILE_PATH "../src/server/cfg.properties"
#define FILES_DIRECTORY_PATH "../src/server/files"

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

#define MAX_CLIENT_NAME 50
#define MAX_CLIENT_ROLE 20

/* STRUCTS */
typedef struct {
    int client_fd;
    time_t last_activity_time;
    char name[MAX_CLIENT_NAME];
    char role[MAX_CLIENT_ROLE];
} client_info_t;

/* GLOBAL VARIABLES */
client_info_t *connected_clients = NULL;
int max_clients = 100;
int current_client_count = 0;
// Estadísticas globales
int total_connections = 0;
int incorrect_lines_received = 0;
int correct_lines_received = 0;
int incorrect_datagrams_received = 0;
int total_files_downloaded = 0;
int total_files_uploaded = 0;

pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

/* FUNCTION PROTOTYPES */
int read_port_from_config();
int read_case_from_config();
int read_idle_timeout_from_config();
int is_us(const char *line, size_t *invalid_pos);
int valid_message(const char *line);
void log_activity(const char *format, ...);
int authenticate_user(const char *credentials, char* name, char *role);
void *handle_client(void *client_socket);
void parse_command(int client_fd, const char* input, const char* role,int case_on);
void handle_auth(int client_fd, const char* username, const char* password);
void handle_list_files(int client_fd);
void handle_echo(int client_fd, const char* text);
void handle_get(int client_fd, const char* filename);
void handle_client_file_transfer(int client_fd);
client_info_t* find_client_by_fd(int client_fd);
int add_client(int client_fd, const char* name, const char* role);
void remove_client(int client_fd);
void handle_tcp_connection(int client_fd);
void handle_udp_datagram(int udp_server_fd);
void update_case(const char *username, int case_on);
void handle_get_base64(const int client_fd, const char* filename);
void send_stats_udp(int udp_server_fd, struct sockaddr_in *client_addr, socklen_t addr_len);
int analyze_command(char* command,char* value,int case_on);
int get_case_by_user(char* username);

int main(void) {
    int server_fd;
    struct sockaddr_in server_addr;

    int udp_server_fd;
    struct sockaddr_in udp_server_addr;

    const int port = read_port_from_config();
    if (port == -1) {
        fprintf(stderr, "ERROR: Could not read the port from config file\n");
        exit(EXIT_FAILURE);
    }

    //TCP Socket
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

    //UDP Socket
    if ((udp_server_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("ERROR: Socket creation failed");
        log_activity("(%s) Socket creation failed", ERROR);
        exit(EXIT_FAILURE);
    }

    memset(&udp_server_addr, 0, sizeof (udp_server_addr));
    udp_server_addr.sin_family = AF_INET;
    udp_server_addr.sin_addr.s_addr = INADDR_ANY;
    udp_server_addr.sin_port = htons(port);

    if (bind(udp_server_fd, (struct sockaddr *) &udp_server_addr, sizeof(udp_server_addr)) == -1) {
        perror("ERROR: Bind failed");
        log_activity("(%s) Bind failed", ERROR);
        close(udp_server_fd);
        exit(EXIT_FAILURE);
    }

    log_activity("(%s) Server started and listening on port: %d", INFO, port);

    fd_set read_fds;
    int max_fd = (server_fd > udp_server_fd) ? server_fd : udp_server_fd;

    while (TRUE) {

        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);  // TCP
        FD_SET(udp_server_fd, &read_fds);  // UDP

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);

        if (activity == -1) {
            perror("ERROR: select() failed");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(server_fd, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            const int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &addr_len);
            total_connections++;

            if (client_fd == -1) {
                perror("ERROR: Accept failed");
                log_activity("(%s) Accept failed", ERROR);
                continue;
            }

            log_activity("(%s) Client connected", INFO);

            handle_tcp_connection(client_fd);
        }

        if (FD_ISSET(udp_server_fd, &read_fds)) {
            handle_udp_datagram(udp_server_fd);
        }

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

int read_case_from_config(){
    FILE *file = fopen(CONFIG_FILE_PATH, "r");
    if (file == NULL) {
        perror("ERROR: Could not open config file");
        return -1;
    }

    char line[BUFFER_SIZE];
    int case_sensitive = -1;

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "case_sensitive=", 15) == 0) {
            if (sscanf(line + 15, "%d", &case_sensitive) != 1) {
                fprintf(stderr, "ERROR: Invalid case value in config file\n");
                fclose(file);
                return -1;
            }
            break;
        }
    }

    fclose(file);
    return case_sensitive;
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

    const time_t now = time(NULL);
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
    const int client_fd = *((int *)client_socket);
    free(client_socket);

    char buffer[BUFFER_SIZE];
    char role[BUFFER_SIZE] = {0};
    char name[MAX_CLIENT_NAME] = {0};
    int authenticated = FALSE;
    time_t last_activity_time = time(NULL);

    log_activity("(%s) New client connection established", INFO);

    while (!authenticated) {
        memset(buffer, 0, BUFFER_SIZE);
        const ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

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

        if (authenticate_user(buffer, name, role)) {
            authenticated = TRUE;
            if (add_client(client_fd, name, role) == -1) {
                log_activity("(%s) Could not add client to connected clients list", ERROR);
                close(client_fd);
                return NULL;
            }
            const char *success_msg = "AUTH_OK\\r\\n";
            send(client_fd, success_msg, strlen(success_msg), 0);
            log_activity("(%s) User authenticated with role: %s", SUCCESS, role);
            correct_lines_received++;
        } else {
            const char *error_msg = "Authentication failed. Try again.\r\n";
            send(client_fd, error_msg, strlen(error_msg), 0);
            log_activity("(%s) Authentication attempt failed", ERROR);
            incorrect_lines_received++;
        }

        last_activity_time = time(NULL);
    }

    while (authenticated) {
        memset(buffer, 0, BUFFER_SIZE);
        const ssize_t bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);

        if (time(NULL) - last_activity_time > read_idle_timeout_from_config()) {
            log_activity("(%s) Client idle timeout reached. Closing connection.", INFO);
            break;
        }

        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                log_activity("(%s) Client disconnected", INFO);
                break;
            }
        }

        buffer[bytes_read] = '\0';
        buffer[strcspn(buffer, "\r\n")] = '\0';

        if (strlen(buffer) == 0) {
            continue;
        }

        log_activity("(%s) Received message: %s", INFO, buffer);

        int case_on = get_case_by_user(name);
        if (case_on == -1)
            case_on = read_case_from_config();

        parse_command(client_fd,buffer,role,case_on);

        if (strcmp(buffer, "logout") == 0) {
            const char *logout_msg = "Logged out. Goodbye!\r\n";
            send(client_fd, logout_msg, strlen(logout_msg), 0);
            log_activity("(%s) User logged out", INFO);
            break;
        }

        const char *response = "Message received.\r\n";
        send(client_fd, response, strlen(response), 0);

        last_activity_time = time(NULL);
        remove_client(client_fd);
    }

    close(client_fd);
    return NULL;
}


int authenticate_user(const char *credentials, char* name, char *role) {
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
                strncpy(name, user, MAX_CLIENT_NAME - 1);
                name[MAX_CLIENT_NAME - 1] = '\0';
                strncpy(role, stored_type, MAX_CLIENT_ROLE - 1);
                role[MAX_CLIENT_ROLE - 1] = '\0';
                role[BUFFER_SIZE - 1] = '\0';
                fclose(file);
                return TRUE;
            }
        }
    }

    fclose(file);
    return FALSE;
}

int analyze_command(char* command,char* value,int case_on){
    if (case_on){
        if (strcmp(command,value) == 0)
            return TRUE;
    }
    else{
        if (strcasecmp(command,value) == 0)
            return TRUE;
    }
    return FALSE;
}

void parse_command(const int client_fd, const char* input,const char* role,int case_on){
    char buffer[BUFFER_SIZE];
    strncpy(buffer, input, BUFFER_SIZE - 1);

    const char* command = strtok(buffer, " ");

    if (command == NULL) {
        incorrect_lines_received++;
        log_activity("(%s) Comando vacío",ERROR);
        return;
    }

    if (analyze_command(command,"AUTH",case_on)) {
        if (!analyze_command(role,"ADMIN",case_on)){
            log_activity("(%s) Usted no es un usuario ADMIN",ERROR);
        }
        else{
            const char* username = strtok(NULL, " ");
            const char* password = strtok(NULL, "\r\n");

            if (username && password) {
                handle_auth(client_fd,username, password);
            } else {
                log_activity("(%s) AUTH requiere un username y password",ERROR);
            }
        }
    } else if (analyze_command(command, "LIST",case_on)) {
        const char* subcommand = strtok(NULL, "\r\n");

        if (subcommand && analyze_command(subcommand, "FILES",case_on)) {
            handle_list_files(client_fd);
            correct_lines_received++;
        } else {
            log_activity("(%s) LIST FILES es el único subcomando válido",ERROR);
            incorrect_lines_received++;
        }
    } else if (analyze_command(command, "ECHO",case_on)) {
        const char* text = strtok(NULL, "\r\n");

        if (text) {
            handle_echo(client_fd,text);
            correct_lines_received++;
        } else {
            log_activity("(%s) ECHO requiere texto",ERROR);
            incorrect_lines_received++;
        }
    } else if (analyze_command(command, "GET",case_on)) {
        const char* subcommand = strtok(NULL, " ");
        const char* filename = strtok(NULL, "\r\n");

        if (subcommand && strcasecmp(subcommand, "base64") == 0 && filename) {
            handle_get_base64(client_fd, filename);
            correct_lines_received++;
        } else if (subcommand) {
            handle_get(client_fd,subcommand);
            correct_lines_received++;
        } else {
            log_activity("(%s) GET requiere un nombre de archivo",ERROR);
            incorrect_lines_received++;
        }
    } else if (strcmp(command, "UPLOAD") == 0) {
        handle_client_file_transfer(client_fd);
        correct_lines_received++;
        log_activity("(%s) File uploaded",INFO);
    }
    else {
        log_activity("(%s) Comando no reconocido",ERROR);
        incorrect_lines_received++;
    }
}

void handle_auth(const int client_fd,const char* username, const char* password) {

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
        const char * message = "User added successfully \n";
        send(client_fd,message, strlen(message),0);
    }
    fclose(file);
    pthread_rwlock_unlock(&rwlock);
}

void handle_list_files(const int client_fd){
    pthread_rwlock_rdlock(&rwlock);

    client_info_t* client = find_client_by_fd(client_fd);

    char path_to_files[BUFFER_SIZE];

    sprintf(path_to_files,"%s/%s",FILES_DIRECTORY_PATH,client->name);

    DIR* directory = opendir(path_to_files);
    if (!directory) {
        perror("ERROR: Could not open files directory");
        log_activity("(%s) Could not open files directory", ERROR);
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    struct dirent* entry;

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            const char * message = strcat(entry->d_name,"\n");
            send(client_fd,message, strlen(message),0);
        }
    }

    closedir(directory);
    pthread_rwlock_unlock(&rwlock);
}

void handle_echo(const int client_fd, const char* text) {
    const size_t message_len = strlen(text) + 2;
    char *message = malloc(message_len);
    if (!message) {
        perror("malloc failed");
        return;
    }

    strcpy(message, text);
    strcat(message, "\n");

    send(client_fd, message, strlen(message), 0);

    free(message);
}

void handle_get(const int client_fd, const char* filename){

    pthread_rwlock_rdlock(&rwlock);

    char buff[BUFFER_SIZE] = FILES_DIRECTORY_PATH;
    const char* path = strcat(strcat(buff,"/"),filename);
    FILE* file = fopen(path,"r");
    if (!file) {
        log_activity("(%s) Could not open (%s) file for reading", ERROR,filename);
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    fseek(file, 0, SEEK_END);
    const long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char size[MAX_LINE_LENGTH];
    sprintf(size, "%ld", file_size);

    char aux[50] = "OK ";

    const char * message = strcat(strcat(aux,size),"\r\n");
    send(client_fd, message, strlen(message),0);

    char line[BUFFER_SIZE];

    while(fgets(line,sizeof(line),file)){
        send(client_fd,line, strlen(line),0);
    }

    total_files_downloaded++;
    fclose(file);
    pthread_rwlock_unlock(&rwlock);
}

void create_directory_if_not_exists(const char *dir_path) {
    char temp_path[PATH_MAX] = "";
    char *token;
    char dir_copy[PATH_MAX];

    // Crear una copia del path porque strtok modifica el string original
    snprintf(dir_copy, sizeof(dir_copy), "%s", dir_path);

    // Separar el path en tokens según el separador '/'
    token = strtok(dir_copy, "/");
    while (token != NULL) {
        // Concatenar el directorio actual al path temporal
        strcat(temp_path, token);
        strcat(temp_path, "/");

        // Verificar si el directorio existe
        struct stat st = {0};
        if (stat(temp_path, &st) == -1) {
            // Si no existe, lo creamos
            if (mkdir(temp_path, 0700) == -1) {
                perror("Error al crear el directorio");
                exit(1);
            }
        }

        // Pasar al siguiente token
        token = strtok(NULL, "/");
    }
}

void handle_client_file_transfer(int client_fd) {
    client_info_t *client = find_client_by_fd(client_fd);
    char buffer[BUFFER_SIZE];
    char dir_path[256];

    const int bytes_received_info = (int) recv(client_fd, buffer, sizeof(buffer), 0);
    if (bytes_received_info <= 0) {
        perror("Error al recibir la información del archivo");
        return;
    }

    buffer[bytes_received_info] = '\0';

    char *file_name = strtok(buffer, "|");
    const char *file_size_str = strtok(NULL, "|");
    const long file_size = strtol(file_size_str, NULL, 10);

    if (file_name == NULL || file_size <= 0) {
        perror("Información del archivo no válida");
        return;
    }

    snprintf(dir_path, sizeof(dir_path), "../src/server/files/%s", client->name);
    create_directory_if_not_exists(dir_path);

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, file_name);

    FILE *file = fopen(file_path, "wb");
    if (file == NULL) {
        perror("Error al abrir el archivo para escritura");
        send(client_fd, "Error: No se pudo crear el archivo", 32, 0);
        return;
    }

    send(client_fd, "READY", 5, 0);

    long total_bytes_received = 0;
    while (total_bytes_received < file_size) {
        const int bytes_received = (int) recv(client_fd, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            perror("Error al recibir el archivo");
            send(client_fd, "Error al recibir el archivo", 27, 0);
            fclose(file);
            return;
        }

        fwrite(buffer, 1, bytes_received, file);
        total_bytes_received += bytes_received;
    }

    send(client_fd, "Success", 7, 0);
    total_files_uploaded++;

    fclose(file);
}

int add_client(const int client_fd, const char* name, const char* role) {
    pthread_rwlock_wrlock(&rwlock);

    if (current_client_count >= max_clients) {
        pthread_rwlock_unlock(&rwlock);
        return FALSE;
    }

    if (connected_clients == NULL) {
        connected_clients = malloc(max_clients * sizeof(client_info_t));
        if (connected_clients == NULL) {
            pthread_rwlock_unlock(&rwlock);
            return FALSE;
        }
    }

    for (int i = 0; i < max_clients; i++) {
        if (connected_clients[i].client_fd == 0) {
            connected_clients[i].client_fd = client_fd;
            connected_clients[i].last_activity_time = time(NULL);
            strncpy(connected_clients[i].name, name, MAX_CLIENT_NAME - 1);
            strncpy(connected_clients[i].role, role, MAX_CLIENT_ROLE - 1);

            current_client_count++;
            pthread_rwlock_unlock(&rwlock);
            return TRUE;
        }
    }

    pthread_rwlock_unlock(&rwlock);
    return FALSE;
}

void remove_client(int client_fd) {
    pthread_rwlock_wrlock(&rwlock);

    for (int i = 0; i < max_clients; i++) {
        if (connected_clients[i].client_fd == client_fd) {
            connected_clients[i].client_fd = 0;
            memset(connected_clients[i].name, 0, MAX_CLIENT_NAME);
            memset(connected_clients[i].role, 0, MAX_CLIENT_ROLE);

            current_client_count--;
            break;
        }
    }

    pthread_rwlock_unlock(&rwlock);
}

client_info_t* find_client_by_fd(const int client_fd) {
    pthread_rwlock_rdlock(&rwlock);

    for (int i = 0; i < max_clients; i++) {
        if (connected_clients[i].client_fd == client_fd) {
            pthread_rwlock_unlock(&rwlock);
            client_info_t* aux = &connected_clients[i];
            printf("Client found: %s\n", aux->name);
            return aux;
        }
    }

    pthread_rwlock_unlock(&rwlock);
    return NULL;
}

void cleanup_client_tracking() {
    if (connected_clients) {
        free(connected_clients);
        connected_clients = NULL;
    }
}

void handle_tcp_connection(int client_fd){
    pthread_t thread_id;
    int *pclient = malloc(sizeof(int));
    if (!pclient) {
        log_activity("(%s) Memory allocation failed for client socket", ERROR);
        close(client_fd);
        return;
    }
    *pclient = client_fd;

    if (pthread_create(&thread_id, NULL, handle_client, pclient) != 0) {
        perror("ERROR: Failed to create thread");
        log_activity("(%s) Failed to create thread", ERROR);
        free(pclient);
        close(client_fd);
        return;
    }

    pthread_detach(thread_id);
}

void handle_udp_datagram(int udp_server_fd) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];
    char role[BUFFER_SIZE] = {0};
    char name[MAX_CLIENT_NAME] = {0};

    ssize_t recv_len = recvfrom(udp_server_fd, buffer, sizeof(buffer) - 1, 0,
                                (struct sockaddr *)&client_addr, &addr_len);
    if (recv_len > 0) {
        buffer[recv_len] = '\0'; // Asegurar que el buffer está null-terminated

        printf("Received UDP datagram: %s\n", buffer);

        // Separar usuario, password y comando
        char *username = strtok(buffer, " ");
        char *password = strtok(NULL, " ");
        char *command = strtok(NULL, " ");

        if (username && password && command) {

            char credentials[MAX_LINE_LENGTH];
            sprintf(credentials,"%s %s\r\n",username,password);

            if (!authenticate_user(credentials,name,role)){
                const char *error_msg = "Authentication failed. Try again.\r\n";
                sendto(udp_server_fd, error_msg, strlen(error_msg), 0,(struct sockaddr *)&client_addr, addr_len);
                log_activity("(%s) Authentication attempt failed", ERROR);
                incorrect_datagrams_received++;
            }
            else{
                const char *success_msg = "Authentication success.\r\n";
                sendto(udp_server_fd, success_msg, strlen(success_msg), 0,(struct sockaddr *)&client_addr, addr_len);
                log_activity("(%s) User authenticated with role: %s", SUCCESS, role);
            }

            // Procesar el comando
            char response[BUFFER_SIZE];

            int case_on = get_case_by_user(username);
            if (case_on == -1)
                case_on = read_case_from_config();

            if (analyze_command(command, "SET",case_on)) {
                // Leer los argumentos adicionales del comando
                char *arg1 = strtok(NULL, " ");
                char *arg2 = strtok(NULL, "\n");


                if (arg1 && arg2 && analyze_command(arg1, "case",case_on)) {
                    if (analyze_command(arg2, "ON",case_on)) {
                        snprintf(response, sizeof(response), "Case-sensitive mode enabled for %s.", username);
                        update_case(username,1);
                    } else if (analyze_command(arg2, "OFF",case_on)) {
                        snprintf(response, sizeof(response), "Case-sensitive mode disabled for %s.", username);
                        update_case(username,0);
                    } else {
                        snprintf(response, sizeof(response), "Invalid argument for SET case: %s", arg2);
                    }
                } else {
                    snprintf(response, sizeof(response), "Invalid SET command format.");
                }
            } else if (analyze_command(command, "STATS\n",case_on)) {
                send_stats_udp(udp_server_fd, &client_addr, addr_len);
            } else {
                snprintf(response, sizeof(response), "Unknown command: %s", command);
                incorrect_datagrams_received++;
            }

            // Enviar la respuesta al cliente
            sendto(udp_server_fd, response, strlen(response), 0,
                   (struct sockaddr *)&client_addr, addr_len);
        } else {
            printf("Malformed datagram: %s\n", buffer);
            char error_response[] = "Invalid datagram format. Expected <username> <password> <command>";
            sendto(udp_server_fd, error_response, strlen(error_response), 0,
                   (struct sockaddr *)&client_addr, addr_len);
            incorrect_datagrams_received++;
        }
    }
}


void update_case(const char *name, int new_value) {
    FILE *file = fopen(CASE_FILE_PATH, "r+"); // Abrir archivo en modo lectura/escritura
    if (file == NULL) {
        perror("Error al abrir el archivo");
    }
    char* username = strtok(name,"=");
    // Obtener el descriptor de archivo para usar flock
    int fd = fileno(file);
    if (flock(fd, LOCK_EX) != 0) { // Bloqueo exclusivo
        perror("Error al bloquear el archivo");
        fclose(file);
    }

    char buffer[MAX_LINE_LENGTH];
    long line_start_pos; // Para recordar la posición de inicio de la línea
    int updated = 0;

    while (fgets(buffer, sizeof(buffer), file)) {
        line_start_pos = ftell(file) - strlen(buffer);

        // Dividir la línea en username y valor
        char *line_username = strtok(buffer, "=");
        char *line_value = strtok(NULL, "\n");

        if (line_username && strcmp(line_username, username) == 0) {
            // Mover el puntero al inicio de la línea
            fseek(file, line_start_pos, SEEK_SET);
            // Sobrescribir la línea con el nuevo valor
            fprintf(file, "%s=%d\n", username, new_value);
            updated = 1;
            break;
        }
    }

    // Liberar el bloqueo
    flock(fd, LOCK_UN);
    fclose(file);

    if (!updated) {
        fprintf(file, "%s=%d\n", username, new_value);
    }
}



void handle_get_base64(const int client_fd, const char* filename) {
    pthread_rwlock_rdlock(&rwlock);

    char filepath[BUFFER_SIZE];
    snprintf(filepath, sizeof(filepath), "%s/%s", FILES_DIRECTORY_PATH, filename);

    FILE *file = fopen(filepath, "r");
    if (!file) {
        const char *error_msg = "ERROR: File not found\r\n";
        send(client_fd, error_msg, strlen(error_msg), 0);
        log_activity("(%s) File not found: %s", ERROR, filename);
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    // Calcular el tamaño del archivo
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Leer el contenido del archivo
    char *file_content = malloc(file_size);
    if (!file_content) {
        const char *error_msg = "ERROR: Memory allocation failed\r\n";
        send(client_fd, error_msg, strlen(error_msg), 0);
        log_activity("(%s) Memory allocation failed", ERROR);
        fclose(file);
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    fread(file_content, 1, file_size, file);
    fclose(file);

    // Codificar en Base64
    size_t encoded_size = ((file_size + 2) / 3) * 4 + 1; // Cálculo del tamaño codificado
    char *encoded_content = malloc(encoded_size + 2); // Agregar espacio para "\r\n"
    if (!encoded_content) {
        const char *error_msg = "ERROR: Memory allocation failed\r\n";
        send(client_fd, error_msg, strlen(error_msg), 0);
        log_activity("(%s) Memory allocation failed", ERROR);
        free(file_content);
        pthread_rwlock_unlock(&rwlock);
        return;
    }

    static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j;
    for (i = 0, j = 0; i < file_size;) {
        uint32_t octet_a = i < file_size ? (unsigned char)file_content[i++] : 0;
        uint32_t octet_b = i < file_size ? (unsigned char)file_content[i++] : 0;
        uint32_t octet_c = i < file_size ? (unsigned char)file_content[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded_content[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded_content[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded_content[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded_content[j++] = base64_table[triple & 0x3F];
    }

    for (size_t padding = 0; padding < (3 - (file_size % 3)) % 3; padding++) {
        encoded_content[--j] = '=';
    }
    encoded_content[j] = '\0';

    // Agregar \r\n al final del contenido codificado
    strcat(encoded_content, "\r\n");

    // Enviar tamaño del archivo codificado
    char response_header[BUFFER_SIZE];
    snprintf(response_header, sizeof(response_header), "OK %zu\r\n", strlen(encoded_content) - 2); // No cuenta el \r\n extra
    send(client_fd, response_header, strlen(response_header), 0);

    // Enviar contenido codificado en Base64
    send(client_fd, encoded_content, strlen(encoded_content), 0);

    log_activity("(%s) File sent in Base64: %s", SUCCESS, filename);
    total_files_downloaded++;

    free(file_content);
    free(encoded_content);
    pthread_rwlock_unlock(&rwlock);
}

void send_stats_udp(int udp_server_fd, struct sockaddr_in *client_addr, socklen_t addr_len) {
    char stats_message[BUFFER_SIZE];
    snprintf(stats_message, sizeof(stats_message),
             "Total Connections: %d\r\n"
             "Incorrect Lines Received: %d\r\n"
             "Correct Lines Received: %d\r\n"
             "Incorrect Datagrams Received: %d\r\n"
             "Total Files Downloaded: %d\r\n"
             "Total Files Uploaded: %d\r\n",
             total_connections, incorrect_lines_received,
             correct_lines_received, incorrect_datagrams_received,
             total_files_downloaded, total_files_uploaded);

    sendto(udp_server_fd, stats_message, strlen(stats_message), 0,
           (struct sockaddr *) client_addr, addr_len);
}

int get_case_by_user(char* username){
    FILE *file = fopen(CASE_FILE_PATH, "r");
    if (file == NULL) {
        perror("ERROR: Could not open case file");
        return -1;
    }

    char line[BUFFER_SIZE];
    int case_sensitive = -1;

    char *name;
    name = strcat(username,"=");
    int length = strlen(name);
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, name, length) == 0) {
            if (sscanf(line + length, "%d", &case_sensitive) != 1) {
                fprintf(stderr, "ERROR: Invalid case value in config file\n");
                fclose(file);
                return -1;
            }
            break;
        }
    }
    fclose(file);
    return case_sensitive;
}
