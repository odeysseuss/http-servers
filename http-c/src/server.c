#include "../include/server.h"

// --- Helper Functions ---

void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    } else {
        return &(((struct sockaddr_in6 *)sa)->sin6_addr);
    }
}

const char *get_mime_type(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";

    if (strcmp(ext, ".html") == 0) return "text/html";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".js") == 0) return "application/javascript";
    if (strcmp(ext, ".json") == 0) return "application/json";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".txt") == 0) return "text/plain";

    return "application/octet-stream";
}

void init_response_header(http_response *res, int status_code, const char *status_text) {
    memset(res, 0, sizeof(http_response));
    strncpy(res->version, "HTTP/1.1", sizeof(res->version)-1);
    res->status_code = status_code;
    strncpy(res->status_text, status_text, sizeof(res->status_text)-1);

    // Add default headers
    char date[64];
    time_t now = time(NULL);
    strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&now));
    add_response_header(res, "Date", date);
    add_response_header(res, "Connection", "close");
}

void add_response_header(http_response *res, const char *name, const char *value) {
    if (res->header_count >= MAX_HEADERS) return;
    strncpy(res->headers[res->header_count][0], name, 255);
    strncpy(res->headers[res->header_count][1], value, 255);
    res->header_count++;
}

void build_response_header(http_response *res, char *buf, size_t buf_size) {
    char *ptr = buf;
    int remaining = buf_size;

    int written = snprintf(ptr, remaining, "%s %d %s\r\n", 
                         res->version, res->status_code, res->status_text);
    ptr += written;
    remaining -= written;

    for (int i = 0; i < res->header_count && remaining > 0; i++) {
        written = snprintf(ptr, remaining, "%s: %s\r\n", 
                         res->headers[i][0], res->headers[i][1]);
        ptr += written;
        remaining -= written;
    }

    if (remaining > 2) {
        memcpy(ptr, "\r\n", 2);
    }
}

void send_http_response(int client_fd, http_response *res, const char *body) {
    char headers[MAX_HEADER_SIZE];
    build_response_header(res, headers, sizeof(headers));
    send(client_fd, headers, strlen(headers), 0);
    if (body) send(client_fd, body, strlen(body), 0);
}

void send_err(int client_fd, int status_code, const char *text) {
    http_response res;
    init_response_header(&res, status_code, text);
    add_response_header(&res, "Content-Type", "text/plain");
    send_http_response(client_fd, &res, text);
}

void handle_get(int client_fd, http_request *req) {
    // Extract path without query parameters
    char path[256] = {0};
    char *query_start = strchr(req->path, '?');

    if (query_start) {
        strncpy(path, req->path, query_start - req->path);
        path[query_start - req->path] = '\0';
    } else {
        strncpy(path, req->path, sizeof(path) - 1);
    }

    // Default to index.html if root is requested
    if (strcmp(path, "/") == 0) {
        strcpy(path, "/index.html");
    }

    // Construct full filesystem path
    char full_path[512];
    snprintf(full_path, sizeof(full_path), "./static%s", path);

    // Security check
    if (strstr(path, "..") != NULL) {
        send_err(client_fd, 403, "Forbidden");
        return;
    }

    // Open the requested file
    FILE *file = fopen(full_path, "rb");
    if (!file) {
        send_err(client_fd, 404, "Not Found");
        return;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Prepare response - ONLY INIT HEADERS HERE
    http_response res;
    init_response_header(&res, 200, "OK");
    add_response_header(&res, "Content-Type", get_mime_type(path));
    add_response_header(&res, "Access-Control-Allow-Origin", "*");

    // Set content length - ONLY ONCE
    char content_length[32];
    snprintf(content_length, sizeof(content_length), "%ld", file_size);
    add_response_header(&res, "Content-Length", content_length);

    // Send headers
    char headers[MAX_HEADER_SIZE];
    build_response_header(&res, headers, sizeof(headers));
    send(client_fd, headers, strlen(headers), 0);

    // Send file content in chunks
    char buffer[BUF_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(client_fd, buffer, bytes_read, 0) < 0) {
            perror("send");
            break;
        }
    }

    fclose(file);
}

int parse_http_request(const char *req, http_request *header) {
    memset(header, 0, sizeof(http_request));
    if (sscanf(req, "%15s %255s %15s", header->method, header->path, header->version) != 3) {
        return -1;
    }

    char *header_start = strstr(req, "\r\n") + 2;
    while (header_start && header->header_count < MAX_HEADERS) {
        char *header_end = strstr(header_start, "\r\n");
        if (!header_end || header_end == header_start) break;

        char *colon = strchr(header_start, ':');
        if (colon) {
            strncpy(header->headers[header->header_count][0], header_start, colon - header_start);
            strncpy(header->headers[header->header_count][1], colon + 2, header_end - (colon + 2));
            header->header_count++;
        }
        header_start = header_end + 2;
    }
    return 0;
}

// Server Core Functions

int setup_server_socket(void) {
    struct addrinfo hints, *servinfo, *p;
    int sockfd, yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, PORT, &hints, &servinfo) != 0) {
        perror("getaddrinfo");
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            close(sockfd);
            freeaddrinfo(servinfo);
            return -1;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "Failed to bind\n");
        return -1;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void handle_client_data(int client_fd) {
    char buf[BUF_SIZE];
    ssize_t len = recv(client_fd, buf, sizeof(buf)-1, 0);

    if (len <= 0) {
        if (len == 0) {
            printf("Client disconnected\n");
        } else {
            perror("recv");
        }
        close(client_fd);
        return;
    }

    buf[len] = '\0';

    http_request req;
    if (parse_http_request(buf, &req) == -1) {
        send_err(client_fd, 400, "Bad Request");
        close(client_fd);
        return;
    }

    if (strcmp(req.method, "GET") == 0) {
        handle_get(client_fd, &req);
    } else {
        send_err(client_fd, 501, "Not Implemented");
    }

    close(client_fd);
}

int main(void) {
    int sockfd = setup_server_socket();
    if (sockfd == -1) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    // Get local IP address
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent *host = gethostbyname(hostname);

    printf("Server running at:\n");
    printf("Local:  http://localhost:%s\n", PORT);
    printf("LAN:    http://%s:%s\n", inet_ntoa(*(struct in_addr*)host->h_addr), PORT);
    printf("Remote: http://103.214.201.216:%s\n", PORT);
    printf("Serving files from ./static/\n");

    while (1) {
        struct sockaddr_storage their_addr;
        socklen_t sin_size = sizeof(their_addr);
        char s[INET6_ADDRSTRLEN];

        int client_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (client_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
                 get_in_addr((struct sockaddr *)&their_addr),
                 s, sizeof(s));
        printf("Connection from %s\n", s);

        if (!fork()) { // Child process
            close(sockfd);
            handle_client_data(client_fd);
            exit(0);
        }
        close(client_fd);
    }

    close(sockfd);
    return 0;
}
