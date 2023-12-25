#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include "sock.h"
#include "packet.h"
#include "util.h"

const int kCodeLength = 6;

static pthread_mutex_t mutex;

typedef enum service_status {
    kWaitingRecv,
    kWaitingAck,
    kWaitingData
} service_status_t;

typedef struct service_entry service_entry_t;

struct service_entry {
    int code;  // generated code
    int clientfd;
    char *pub_key;
    service_status_t status;
    service_entry_t *left;
    service_entry_t *right;
};

service_entry_t *root_entry;

static int gen_code(int code_length) {
    srand(time(NULL));
    return rand() % (int)pow(10, code_length);
}

static service_entry_t *create_entry(int clientfd, int code_length) {
    service_entry_t *new_entry = malloc(sizeof(service_entry_t));
    new_entry->code = gen_code(code_length);
    new_entry->clientfd = clientfd;
    new_entry->status = kWaitingRecv;
    new_entry->pub_key = NULL;
    new_entry->left = NULL;
    new_entry->right = NULL;
    return new_entry;
}

static service_entry_t *insert_entry(service_entry_t* entry) {
    if (root_entry == NULL) return entry;
    service_entry_t *cur_entry = root_entry;
    do {
        if (entry->code < cur_entry->code) {
            if (cur_entry->left == NULL) {
                cur_entry->left = entry;
                break;
            } else cur_entry = cur_entry->left;
        } else {
            if (cur_entry->right == NULL) {
                cur_entry->right = entry;
                break;
            } else cur_entry = cur_entry->right;
        }
    } while (1);
    return root_entry;
}

static service_entry_t *search_entry(int code) {
    service_entry_t *cur_entry = root_entry;
    while (1) {
        if (cur_entry != NULL) {
            if (code == cur_entry->code)
                return cur_entry;
            else if (code < cur_entry->code)
                cur_entry = cur_entry->left;
            else
                cur_entry = cur_entry->right;
        } else {  // not found
            return NULL;
        }
    }
}

static void die(char *msg)
{
    printf("%s\n", msg);
    exit(-1);
}

static void *serve(void *argp)
{
    long clientfd = (long)argp;
    // do something
    packet_header_t *recv_header = malloc(sizeof(packet_header_t));
    packet_payload_t *recv_payload = malloc(sizeof(packet_payload_t));
    packet_header_t *send_header = malloc(sizeof(packet_header_t));
    packet_payload_t *send_payload = malloc(sizeof(packet_payload_t));
    if (recv(clientfd, recv_header, sizeof(packet_header_t), 0) == -1) {
        printf("error: clientfd: %ld. Invalid packet\n", clientfd);
        return 0;
    }
    if (recv_header->opcode == kOpCreate) {  // sender request
        service_entry_t *new_entry = create_entry(clientfd, kCodeLength);
        pthread_mutex_lock(&mutex);
        root_entry = insert_entry(new_entry);
        pthread_mutex_unlock(&mutex);
        pack_packet_header(send_header, kOpAck, kCode, sizeof(const int));
        send(clientfd, send_header, sizeof(packet_header_t), 0);
        pack_packet_payload(send_payload,
                            0, sizeof(const int), (char *)&new_entry->code);
        send(clientfd, send_payload, sizeof(packet_payload_t), 0);
        
        // wait until receiver public key delivered
        while (new_entry->pub_key == NULL);
        pack_packet_header(send_header, kOpPub, kPubKey, 64);
        send(clientfd, send_header, sizeof(packet_header_t), 0);
        pack_packet_payload(send_payload,
                            0, 64, (char *)&new_entry->pub_key);
        send(clientfd, send_payload, sizeof(packet_payload_t), 0);

        // wait sender ack
        do {
            while (recv(clientfd, recv_header, 
                        sizeof(packet_header_t), 0) == -1);
        } while (recv_header->opcode != kOpAck);

    } else if (recv_header->opcode == kOpRequest) {  // receiver request
        // receive code
        if (recv(clientfd, recv_payload, sizeof(packet_payload_t), 0) == -1) {
            printf("error: recv code payload. clientfd: %ld.\n", clientfd);
            return 0;
        }
        int recv_code = (int)*recv_payload->payload;
        
        // receive public key
        if (recv(clientfd, recv_payload, sizeof(packet_payload_t), 0) == -1) {
            printf("error: recv code payload. clientfd: %ld.\n", clientfd);
            return 0;
        }
        char *pub_key = malloc(recv_payload->cur_payload_size);
        strncpy(pub_key, recv_payload->payload, recv_payload->cur_payload_size);
        
        service_entry_t *entry = search_entry(recv_code);
        if (entry) {
            entry->pub_key = pub_key;
            pack_packet_header(send_header, kOpAck, kNone, 0);
            send(clientfd, send_header, sizeof(packet_header_t), 0);
        } else {
            pack_packet_header(send_header, kOpError, kNone, 0);
            send(clientfd, send_header, sizeof(packet_header_t), 0);
            printf("error: recv code not found. clientfd: %ld.\n", clientfd);
            return 0;
        }
        
    } else {  // invalid situation
        printf("error: clientfd: %ld. Invalid packet_header opcode: %d\n", 
               clientfd, recv_header->opcode);
        return 0;
    }
    return 0;
}

int main(int argc , char *argv[]) {
    char *server_port = NULL;
    --argc; ++argv;
    if (argc > 0 && **argv == '-' && (*argv)[1] == 'p') {
        --argc; ++argv;
        if (argc < 1)
            die("error: No port number provided\n");

        server_port = malloc(strlen(*argv) + 1);
        strncpy(server_port, *argv, strlen(*argv));
        --argc; ++argv;

        if (argc > 0)
            die("error: too many arguments");
    } else {
        die("usage: servr -p server_port\n");
    }

    int listenfd __attribute__((unused)) = open_listenfd(server_port);
    if (listenfd == -1) {
        printf("Unable to open with port: %s\n", server_port);
        return -1;
    }
    printf("listening on the port %s\n", server_port);

    pthread_mutex_init(&mutex, NULL);
    while (1) {
        struct sockaddr client_info;
        socklen_t addrlen;
        long clientfd = accept(listenfd, &client_info, &addrlen);
        pthread_t thread;
        pthread_create(&thread, NULL, serve, (void *)clientfd);
        printf("info: thread %ld created, serving connection fd %ld\n",
               (long)thread, clientfd);
    }
    pthread_mutex_destroy(&mutex);

    return 0;
}
