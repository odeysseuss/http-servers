#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>

#define PORT "3490"
#define BACKLOG 10
#define INITIAL_FD_SIZE 5
#define MAX_HEADERS 20
#define MAX_HEADER_SIZE 1024
#define BUF_SIZE 8192

typedef struct {
    char method[16];
    char path[256];
    char version[16];
    char headers[MAX_HEADERS][2][256];
    int header_count;
} http_request;

typedef struct {
    char version[16];
    int status_code;
    char status_text[64];
    char headers[MAX_HEADERS][2][256];
    int header_count;
} http_response;

void *get_in_addr(struct sockaddr *sa);
int sendall(int fd, char *buf, int *len);
void add_to_pfds(struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size);
void del_from_pfds(struct pollfd pfds[], int i, int *fd_count);
const char* get_mime_type(const char *path);
int parse_http_request(const char *req, http_request *header);
void add_response_header(http_response *res, const char *name, const char *value);
void init_response_header(http_response *res, int status_code, const char *status_text);
void build_response_header(http_response *res, char *buf, size_t buf_size);
void send_http_response(int client_fd, http_response *res, const char *body);
void handle_get(int client_fd, http_request *header);
const char *get_content_type(const char *path);
void send_err(int client_fd, int status_code, const char *text);
