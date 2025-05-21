#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>

////////////////////////////////

#ifdef _WIN32
#include <winsock2.h>
#define SHUT_RDWR SD_BOTH
#define MSG_NOSIGNAL 0
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

////////////////////////////////

typedef uint8_t byte;
typedef uint16_t u16;
typedef uint32_t u32;

#define prefix(s1, s2) (!strncmp(s1, s2, strlen(s2)))

// NOTE(w): legacy, rework this
#define T_USER 1
//#define T_KEYSUM 0
//#define T_BYE 3

////////////////////////////////
// Message format
// HEADER
//   1b type
//   1b nonce (used in encryption)
//   2b len   (of the message)
//   2b userid
// BODY
//   lenXb encrypted message

////////////////////////////////
// Helpers

// Why doesn't windows have this function?
#ifdef _WIN32
size_t getline(char **lineptr, size_t *n, FILE *stream) {
    assert(*lineptr == NULL);
    // I hope you don't need more than 1024 chars...
    *n = 1024;
    *lineptr = malloc(1024);
    
    if (fgets(*lineptr, 1024, stream) == NULL) {
        perror("fgets()");
        exit(1);
    }
    
    return strlen(*lineptr);
}
#endif

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

int parseip(const char *ip, u32 *addr, u16 *p) {
    byte a, b, c, d;
    u16 port;
    
    if (sscanf(ip,
               "%hhu.%hhu.%hhu.%hhu:%hu",
               &a, &b, &c, &d, &port) < 5) {
        return 1;
    }
    
    *addr = 0;
    *addr = d | (c << 8) | (b << 16) | (a << 24);
    
    *p = port;
    
    return 0;
}

char *query_key(void) {
    char *key = NULL;
    size_t sz;
    ssize_t len;
    
    printf("Enter preshared key: ");
    
    len = getline(&key, &sz, stdin);
    
    if (len < 0) {
        perror("getline()");
        exit(1);
    }
    
    if (len <= 1) {
        printf("Key should be at least 2 bytes long\n");
        exit(1);
    }
    
    key[len-1] = 0;
    
    return key;
}

char *gen_userid(void) {
    static char userid[2];
    
    srand(time(NULL));
    userid[0] = rand()%95+32;
    userid[1] = rand()%95+32;
    
    return userid;
}

void sockperror(const char *str) {
#ifdef _WIN32
    int err = WSAGetLastError();
    char *msg = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_SYSTEM,
                   NULL, err, 0, (LPSTR)&msg, 0, NULL);
    printf("%s: %s\n", str, msg);
    LocalFree(msg);
#else
    perror(str);
#endif
}

////////////////////////////////
// Cryptography
// NOTE(w): this cryptography is rather weak.
// I think it could rather easily be cracked,
// but at the same time, no one knows this 
// chat protocol.
// Thus we achieve security through obscurity.


// Vigere XOR cypher
byte *xoronce(byte *text, size_t len, const byte *key, char nonce) {
    size_t keylen = strlen((char*)key);
    
    assert(keylen > 0);
    
    for (size_t i = 0 ; i < len; i++) {
        size_t off = i%keylen;
        text[i] ^= key[off] ^ nonce;
    }
    
    return text;
}

byte *encrypt(byte *text,
              size_t len,
              byte *key,
              char nonce) {
    
    for (size_t i = 0; i < len; i++) {
        xoronce(text+i, len-i, key, nonce|i);
    }
    
    return text;
}

byte *decrypt(byte *text,
              size_t len,
              byte *key,
              char nonce) {
    
    for (ssize_t i = len-1; i >= 0; i--) {
        xoronce(text+i, len-i, key, nonce|i);
    }
    
    return text;
}


////////////////////////////////

void dosend(int fd, byte *data, size_t len) {
    if (send(fd, data, len, MSG_NOSIGNAL) < 0) {
        sockperror("send()");
        exit(1);
    }
}

void sendmessage(int fd, char *userid, char *msg, char *key, byte nonce) {
    byte hdr[6];
    
    size_t msglen = strlen(msg);
    
    assert(msglen);
    
    if (msglen > 65535) {
        printf("Your message is too long\n"
               "It is going to be cropped\n");
        msglen = 65535;
    }
    
    hdr[0] = T_USER;
    hdr[1] = nonce;
    hdr[2] = msglen & 0xFF;
    hdr[3] = (msglen & 0xFF00) >> 8;
    hdr[4] = userid[0];
    hdr[5] = userid[1];
    
    dosend(fd, hdr, 6);
    
    encrypt((byte*)msg, msglen, (byte*)key, nonce);
    
    dosend(fd, (byte*)msg, msglen);
}

////////////////////////////////

// Receive one message from fd
byte *receive(int fd, size_t *sz) {
    assert(fd >= 0);
    
    byte buf[128];
    byte *data = NULL;
    ssize_t res = 0;
    
    *sz = 0;
    
    while (1) {
        if ((res = recv(fd, buf, 128, 0)) < 0) {
            sockperror("recv()");
            exit(1);
        }
        // The connection was closed (gracefully)
        if (res == 0) {
            printf("The server has disconnected\n");
            exit(1);
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
    
    return data;
}

// Receive all messages and print them
void receive_all_and_print(int fd, char *key
#ifdef GUI_CLIENT
                           , char ***msgs,
                           int *msgs_n
#endif
                           ) {
    while (1) {
        fd_set readfs;
        FD_ZERO(&readfs);
        FD_SET(fd, &readfs);
        
        struct timeval timeout = {0};
        
        int ret = select(fd+1, &readfs, NULL, NULL, &timeout);
        
        // Nothing to receive
        if (ret == -1 || !FD_ISSET(fd, &readfs)) break;
        
        size_t sz;
        byte *data = receive(fd, &sz);
        
        if (sz < 6) {
            printf("Malformed message received\n");
            free(data);
            break;
        }
        
        size_t len = sz-6;
        byte nonce = data[1];
        char *id = (char*)data+4;
        
        decrypt(data+6, len, (byte*)key, nonce);
        
        char msg[len+1];
        memcpy(msg, data+6, len);
        msg[len] = 0;
        
#ifndef GUI_CLIENT
        printf("[%c%c] %s\n", id[0], id[1], msg);
#else
        char *fullmsg = malloc(len+5+1);
        snprintf(fullmsg, len+5+1, "[%c%c] %s", id[0], id[1], msg);
        
        (*msgs_n)++;
        *msgs = realloc(*msgs, sizeof(char*)*(*msgs_n));
        (*msgs)[*msgs_n-1] = fullmsg;
#endif
        
        free(data);
    }
}

////////////////////////////////

int finish = 0;
void intrhandle(int _sig) {
    (void)_sig;
    finish = 1;
}

////////////////////////////////

#ifndef GUI_CLIENT
int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Provide the ip and port of the server\n");
        return 1;
    }
    
    u32 addr;
    u16 port;
    
    if (parseip(argv[1], &addr, &port)) {
        printf("Malformed ip address\n"
               "Should match XXX.XXX.XXX.XXX:PORT\n");
        return 1;
    }
    
    printf("Server: %s:%d\n", strip(addr), port);
    
    signal(SIGINT, intrhandle);
    
    ////////////////////////////////
    
    char *key = query_key();
    
    ////////////////////////////////
    
    char *userid = gen_userid();
    printf("Your id is '%c%c'\n", userid[0], userid[1]);
    
    ////////////////////////////////
    
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    ////////////////////////////////
    // Connect
    
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(addr);
    sa.sin_port = htons(port);
    
    if (connect(fd, (struct sockaddr*)&sa, sizeof(struct sockaddr_in)) < 0) {
        sockperror("connect()");
        return 1;
    }
    
    printf("Connection to server has been established\n");
    
    ////////////////////////////////
    // Main loop
    
    byte nonce = 0;
    
    while (!finish) {
        receive_all_and_print(fd, key);
        
        ////////////////////////////////
        
        printf("> ");
        char *line = NULL;
        size_t sz;
        ssize_t len;
        
        len = getline(&line, &sz, stdin);
        
        if (len < 0) {
            perror("getline()");
            free(line);
            break;
        }
        
        if (len <= 1) {
            free(line);
            continue;
        }
        
        line[len-1] = 0;
        
        ////////////////////////////////
        
        nonce++;
        sendmessage(fd, userid, line, key, nonce);
        
        free(line);
    }
    
    shutdown(fd, SHUT_RDWR);
}
#else
#include <raylib.h>

#define RAYGUI_IMPLEMENTATION
// NOTE(w): Just enough to fit the text (text is 0.04)
#define RAYGUI_MESSAGEBOX_BUTTON_HEIGHT floorf(0.045*GetScreenHeight())
#define RAYGUI_TEXTINPUTBOX_BUTTON_HEIGHT floorf(0.045*GetScreenHeight())
#define RAYGUI_TEXTINPUTBOX_HEIGHT floorf(0.045*GetScreenHeight())
#include "raygui.h"

// I don't know why raylib includes pressing escape as a reason
// for WindowShouldClose() by default
#define CLOSE() (WindowShouldClose() && !IsKeyPressed(KEY_ESCAPE))

#define RELRECT(x,y,w,h) (Rectangle){x*GetScreenWidth(), y*GetScreenHeight(), w*GetScreenWidth(), h*GetScreenHeight()}

char *trimleft(char *str) {
    for(;isspace(*str); str++);
    return str;
}

int try_connect(u32 addr, u16 port) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(addr);
    sa.sin_port = htons(port);
    
    if (connect(fd, (struct sockaddr*)&sa, sizeof(struct sockaddr_in)) < 0) {
        sockperror("connect()");
        return -1;
    }
    
    return fd;
}

int main(void) {
    SetConfigFlags(FLAG_WINDOW_RESIZABLE);
    InitWindow(480, 660, "guitext");
    SetTargetFPS(60);
    
    Font font = LoadFontEx("CascadiaCode.ttf", 50, NULL, 0);
    SetTextureFilter(font.texture, TEXTURE_FILTER_BILINEAR);
    GuiSetFont(font);
    GuiSetStyle(DEFAULT, TEXT_SIZE, 27);
    
    char **msgs = NULL;
    char *userid;
    int running = 1, finish_query = 0, msgs_n = 0, connected = 0, connect_popup = 0, have_key = 0;
    int fd = -1;
    byte nonce;
    char input[128], ipinput[128], key[128];
    memset(input, 0, 128);
    memset(ipinput, 0, 128);
    memset(key, 0, 128);
    
    // Message threshold
    int msg_t = 16;
    
    while (!CLOSE() && running) {
        BeginDrawing();
        ClearBackground(GetColor(GuiGetStyle(DEFAULT, BACKGROUND_COLOR)));
        
        GuiSetStyle(DEFAULT, TEXT_SIZE, floorf(0.04*GetScreenHeight()));
        
        if (connected)
            receive_all_and_print(fd, key, &msgs, &msgs_n);
        
        int beg = 0;
        if (msgs_n >= msg_t) beg = msgs_n-msg_t;
        for (int i = beg; i < msgs_n; i++) {
            GuiLabel(RELRECT(0.062, (0.055 + 0.05*(i-beg+1)), 0.94, 0.05), msgs[i]);
        }
        
        if (GuiButton(RELRECT(0.05, 0.036, 0.25, 0.045), "Exit")) {
            finish_query = 1;
        }
        
        if (finish_query) {
            int res = GuiMessageBox(RELRECT(0.18, 0.1, 0.52, 0.15), "", "Are you sure?", "Exit");
            if (res >= 0) finish_query = 0;
            if (res == 1) running = 0;
        }
        
        ////////////////////////////////
        
        if (!have_key) {
            int res = GuiTextInputBox(RELRECT(0.18, 0.1, 0.5, 0.2), "", "Input preshared key", "Exit;Done", key, 128, 0);
            if (res == 1) {
                exit(0);
            }
            if (res == 2) {
                if (strlen(key) <= 2) {
                    EndDrawing();
                    continue;
                }
                have_key = 1;
                
                userid = gen_userid();
                char *msg = malloc(16+1);
                snprintf(msg, 16+1, "Your id is '%c%c'", userid[0], userid[1]);
                msgs_n++;
                msgs = realloc(msgs, sizeof(char*)*msgs_n);
                msgs[msgs_n-1] = msg;
            }
        }
        
        ////////////////////////////////
        
        if (!connected) {
            if (GuiButton(RELRECT(0.7, 0.036, 0.25, 0.045), "Connect")) {
                connect_popup = 1;
            }
        }
        else {
            if (GuiButton(RELRECT(0.7, 0.036, 0.25, 0.045), "Disconnect")) {
                connected = 0;
            }
        }
        
        
        if (connect_popup) {
            int res = GuiTextInputBox(RELRECT(0.18, 0.1, 0.5, 0.2), "", "Input ip with port", "Abort;Done", ipinput, 128, 0);
            if (res >= 0) connect_popup = 0;
            if (res == 2) {
                u32 addr;
                u16 port;
                if(parseip(ipinput, &addr, &port)) {
                    char *msg = malloc(17+1);
                    snprintf(msg, 17+1, "Invalid ip format");
                    msgs_n++;
                    msgs = realloc(msgs, sizeof(char*)*msgs_n);
                    msgs[msgs_n-1] = msg;
                    EndDrawing();
                    continue;
                }
                fd = try_connect(addr, port);
                if (fd < 0) {
                    char *msg = malloc(19+1);
                    snprintf(msg, 19+1, "Connection refused");
                    msgs_n++;
                    msgs = realloc(msgs, sizeof(char*)*msgs_n);
                    msgs[msgs_n-1] = msg;
                    EndDrawing();
                    continue;
                }
                connected = 1;
            }
        }
        
        ////////////////////////////////
        
        if (GuiTextBox(RELRECT(0.083, 0.9, 0.83, 0.05), input, 128, connected)) {
            printf("Text box input: %s\n", input);
            char *i = trimleft(input);
            if (strlen(i)) {
                char *msg = malloc(strlen(i)+1);
                strcpy(msg, i);
                msgs_n++;
                msgs = realloc(msgs, sizeof(char*)*msgs_n);
                msgs[msgs_n-1] = msg;
                
                nonce++;
                sendmessage(fd, userid, i, key, nonce);
                memset(input, 0, 128);
            }
        }
        
        EndDrawing();
    }
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
    UnloadFont(font);
}
#endif