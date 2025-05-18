#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

////////////////////////////////

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  byte;

typedef struct Conn Conn;
struct Conn {
    int fd;
    int marked;
    u32 addr;
    u16 port;
};

////////////////////////////////
// Helpers

char *strip(uint32_t ip) {
    static char buf[16] = {0};
    snprintf(buf, 16, "%d.%d.%d.%d",
             (ip & 0xFF000000)>>24,
             (ip & 0xFF0000)>>16,
             (ip & 0xFF00)>>8,
             ip & 0xFF);
    return buf;
}

// Convert from little-endian to host endianess
u16 h16(byte *data) {
    return data[0] | ((u16)data[1] << 8);
}

////////////////////////////////

void accept_all(int server, Conn **conns, size_t *n) {
    struct sockaddr_in saddr;
    socklen_t len = sizeof(struct sockaddr_in);
    
    int fd = accept(server, (struct sockaddr*)&saddr, &len);
    
    if (fd < 0) {
        if (errno == EWOULDBLOCK) return;
        if (errno = ECONNABORTED) return;
        perror("accept()");
        return;
    }
    
    ////////////////////////////////
    // Convert to host byte order
    
    u16 port = ntohs(saddr.sin_port);
    u32 addr = ntohl(saddr.sin_addr.s_addr);
    
    printf("Accepted %s:%d\n", strip(addr), port);
    
    
    ////////////////////////////////
    // Append to the array of connections
    
    (*n)++;
    *conns = realloc(*conns, sizeof(Conn)*(*n));
    (*conns)[*n-1] = (Conn) {
        .addr = addr,
        .port = port,
        .fd = fd
    };
}

////////////////////////////////

// Receive one message from fd
byte *receive(int fd, size_t *sz, int *close) {
    assert(fd >= 0);
    
    byte buf[128];
    byte *data = NULL;
    ssize_t res = 0;
    
    *sz = 0;
    
    while (1) {
        if ((res = recv(fd, buf, 128, 0)) < 0) {
            perror("recv()");
            if (data != NULL) free(data);
            return NULL;
        }
        if (!res) {
            *close = 1;
            return NULL;
        }
        *sz += res;
        // Append the data
        data = realloc(data, *sz);
        memcpy(data+*sz-res, buf, res);
        // Haven't received the header yet
        if (*sz < 6) continue;
        // Haven't received the full message length
        if (*sz < (size_t)(h16(data+2)+(u16)6)) continue;
        break;
    }
    
    printf("Received data\n");
    
    return data;
}

void dosend(Conn *c, byte *data, size_t len) {
    if (send(c->fd, data, len, MSG_NOSIGNAL) < 0) {
        perror("send()");
        c->marked = 1;
    }
}

// Resend data to all but the user who sent it
void resend(byte *data, size_t sz,
            Conn c, Conn **conns, size_t *n) {
    assert(data != NULL);
    
    for (size_t i = 0; i < *n; i++) {
        if ((*conns)[i].fd == c.fd) continue;
        dosend(&((*conns)[i]), data, sz);
    }
}

void receive_and_resend(Conn **conns, size_t *n) {
    ////////////////////////////////
    // Poll
    
    struct pollfd fds[*n];
    
    for (size_t i = 0; i < *n; i++) {
        fds[i].fd = (*conns)[i].fd;
        fds[i].events = POLLIN | POLLHUP;
    }
    
    int ret = poll(fds, *n, 300);
    
    if (ret <= 0) return;
    ////////////////////////////////
    // Receive
    
    for (size_t i = 0; i < *n; i++) {
        // Mark for deletion
        if (fds[i].revents & (POLLHUP|POLLERR|POLLNVAL)) {
            (*conns)[i].marked = 1;
        }
        // Receive
        else if (fds[i].revents & POLLIN) {
            size_t sz;
            int close = 0;
            byte *data = receive(fds[i].fd, &sz, &close);
            if (close) {
                (*conns)[i].marked = 1;
                continue;
            }
            if (data != NULL) {
                resend(data, sz, (*conns)[i], conns, n);
                free(data);
            }
        }
    }
}

////////////////////////////////

void delete_marked(Conn **conns, size_t *n) {
    size_t n2 = 0;
    
    for (size_t i = 0; i < *n; i++) {
        if (!(*conns)[i].marked) n2++;
    }
    
    // No connection is marked
    if (*n == n2) return;
    
    Conn *conns2 = malloc(sizeof(Conn)*n2);
    
    // Filter
    size_t j = 0;
    for (size_t i = 0; i < *n; i++) {
        if (!(*conns)[i].marked) {
            conns2[j] = (*conns)[i];
            j++;
            continue;
        }
        printf("Deleting %s:%d\n",
               strip((*conns)[i].addr),
               (*conns)[i].port);
    }
    
    free(*conns);
    
    *n = n2;
    *conns = conns2;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Provide listen port\n");
        return -1;
    }
    
    int lport = atoi(argv[1]);
    
    if (lport <= 0) {
        printf("Invalid port\n");
        return -1;
    }
    
    int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if (server < 0) {
        perror("socket()");
        return 1;
    }
    
    ////////////////////////////////
    // Allow reuse
    
    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    ////////////////////////////////
    
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(lport);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    
    if(bind(server, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        perror("bind()");
        close(server);
        return 1;
    }
    
    ////////////////////////////////
    // Set non-blocking
    int flags = fcntl(server, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl()");
        close(server);
        return 1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(server, F_SETFL, flags)) {
        perror("fcntl()");
        close(server);
        return 1;
    }
    
    ////////////////////////////////
    
    if (listen(server, 8) < 0) {
        perror("listen()");
        close(server);
        return 1;
    }
    
    printf("Listening on %d\n", lport);
    
    ////////////////////////////////
    // Main loop
    
    Conn *conns = NULL;
    size_t conns_n = 0;
    
    for (;;) {
        accept_all(server, &conns, &conns_n);
        receive_and_resend(&conns, &conns_n);
        delete_marked(&conns, &conns_n);
        usleep(1000 * 200);
    }
}