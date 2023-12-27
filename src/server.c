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
    char *name;
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

static service_entry_t *create_entry(int clientfd, int code_length, 
                                     char *name) {
    service_entry_t *new_entry = malloc(sizeof(service_entry_t));
    new_entry->code = gen_code(code_length);
    new_entry->clientfd = clientfd;
    new_entry->status = kWaitingRecv;
    new_entry->name = name;
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

static service_entry_t *send_intention_handler(long clientfd, int name_length) {
    int status = 0;
    printf("info: receive send intention. (%ld)\n", clientfd);
    // receive name payload
    packet_payload_t recv_name_payload = 
        malloc(GET_PAYLOAD_PACKET_LEN(name_length));
    status = recv(clientfd, recv_name_payload, 
                  GET_PAYLOAD_PACKET_LEN(name_length), 0);
    if (status == -1) {
        printf("error: recv name payload. (%ld)\n", clientfd);
        return NULL;
    }
    char *name;
    if (copy_payload(recv_name_payload, &name) == -1 || name[0] == 0) {
        printf("error: parsing name. (%ld)\n", clientfd);
        return NULL;
    }
    printf("info: name payload received: %s (%ld)\n", name, clientfd);
    
    service_entry_t *new_entry = create_entry(clientfd, kCodeLength, name);
    pthread_mutex_lock(&mutex);
    root_entry = insert_entry(new_entry);
    pthread_mutex_unlock(&mutex);
    printf("info: entry creation complete, code = %d (%ld)\n",
           new_entry->code, clientfd);
    
    // send code header
    printf("info: send ack header (%ld)\n", clientfd);
    packet_header_t send_header;
    create_header(&send_header, kOpAck, kCode, sizeof(const int));
    send(clientfd, send_header, HEADER_LENGTH, 0);
    
    // send code payload
    printf("info: send code payload (%ld)\n", clientfd);
    packet_payload_t send_code_payload;
    create_payload(&send_code_payload, 0, sizeof(const int),
                   (char *)&new_entry->code);
    send(clientfd, send_code_payload, 
         GET_PAYLOAD_PACKET_LEN(sizeof(const int)), 0);
    free(recv_name_payload);
    return new_entry;
}

static int send_pub_key_handler(long clientfd, service_entry_t *entry) {
    int status = 0;
    packet_header_t send_pub_key_header;
    if (create_header(&send_pub_key_header, kOpPub, kPubKey, 64) == -1) {
        printf("error: create pubkey header failed. (%ld)\n", clientfd);
        return -1;
    }
    send(clientfd, send_pub_key_header, HEADER_LENGTH, 0);

    packet_payload_t send_pub_key_payload;
    int packet_length = create_payload(&send_pub_key_payload, 0, 
                                       64, (char *)&entry->pub_key);
    if (packet_length == -1) {
        printf("error: create pubkey payload failed. (%ld)\n", clientfd);
        return -1;
    }
    send(clientfd, send_pub_key_payload, packet_length, 0);
    
    // wait sender ack
    packet_payload_t recv_ack_header = malloc(HEADER_LENGTH);
    status = recv(clientfd, recv_ack_header, HEADER_LENGTH, 0);
    if (status == -1) {
        printf("error: receive ack pubkey ack failed. (%ld)\n", clientfd);
    } else if (status == 0) {
        printf("error: receiver disconnected. (%ld)\n", clientfd);
        status = -1;
    } else if (get_opcode(recv_ack_header) != kOpAck) {
        printf("error: wrong opcode. (%ld)\n", clientfd);
        status = -1;
    }
    free(recv_ack_header);
    return status;
}

static int receiver_request_handler(long clientfd) {
    printf("info: receive request intention. (%ld)\n", clientfd);
    int status = 0;
    // receive code
    packet_payload_t recv_code_payload = 
        malloc(GET_PAYLOAD_PACKET_LEN(sizeof(int)));
    status = recv(clientfd, recv_code_payload,
                  GET_PAYLOAD_PACKET_LEN(sizeof(int)), 0);
    if (status == -1) {
        printf("error: recv code payload. (%ld).\n", clientfd);
        goto REQ_ERR_RET0;
    }
    int *recv_code;
    copy_payload(recv_code_payload, (char **)&recv_code);
    printf("info: recv code payload = %d. (%ld)\n", *recv_code, clientfd);
    
    // receive public key
    packet_payload_t recv_pubkey_payload = 
        malloc(GET_PAYLOAD_PACKET_LEN(64));
    status = recv(clientfd, recv_pubkey_payload, GET_PAYLOAD_PACKET_LEN(64), 0);
    if (status == -1) {
        printf("error: recv code payload. (%ld)\n", clientfd);
        goto REQ_ERR_RET1;
    }
    char *pub_key;
    copy_payload(recv_pubkey_payload, &pub_key);
    printf("info: recv pub_key payload = %s. (%ld)\n", pub_key, clientfd);
    
    service_entry_t *entry = search_entry(*recv_code);
    packet_header_t send_ack_header;
    if (entry) {
        entry->pub_key = pub_key;
        create_header(&send_ack_header, kOpAck, kNone, 0);
        send(clientfd, send_ack_header, HEADER_LENGTH, 0);
    } else {
        create_header(&send_ack_header, kOpError, kNone, 0);
        send(clientfd, send_ack_header, HEADER_LENGTH, 0);
        printf("error: recv code not found. (%ld)\n", clientfd);
        status = -1;
    }
    free(send_ack_header);
REQ_ERR_RET1:
    free(recv_pubkey_payload);
REQ_ERR_RET0:
    free(recv_code_payload);
    return status;
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
    int status = 0;
    packet_header_t recv_header = malloc(HEADER_LENGTH + 1);
    status = recv(clientfd, recv_header, HEADER_LENGTH, 0);
    if (status == -1) {
        printf("error: invalid packet header. (%ld-%d)\n", clientfd, status);
        return 0;
    }
    if (get_opcode(recv_header) == kOpCreate) {  // sender request
        
        // handler send file intention
        service_entry_t *new_entry = 
            send_intention_handler(clientfd, get_payload_length(recv_header));
        if (new_entry == NULL) {
            printf("error: handle sender intention failed. (%ld)\n", clientfd);
            return 0;
        }
        
        // wait until receiver public key delivered
        while (new_entry->pub_key == NULL);
        if (send_pub_key_handler(clientfd, new_entry) == -1) {
            printf("error: handle pubkey intention failed. (%ld)\n", clientfd);
            return 0;
        }
    } else if (get_opcode(recv_header) == kOpRequest) {  // receiver request
        if (receiver_request_handler(clientfd) == -1) {
            printf("error: handle receive intention failed. (%ld)\n", clientfd);
            return 0;
        }
    } else {  // invalid situation
        printf("error: clientfd: %ld. Invalid packet_header opcode: %d\n", 
               clientfd, get_opcode(recv_header));
        return 0;
    }
    close(clientfd);
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
        printf("error: Unable to open with port: %s\n", server_port);
        return -1;
    }
    printf("listening on the port %s\n", server_port);

    pthread_mutex_init(&mutex, NULL);
    while (1) {
        struct sockaddr client_info;
        socklen_t addrlen;
        long clientfd = accept(listenfd, &client_info, &addrlen);
        if (clientfd == -1) continue;
        pthread_t thread;
        pthread_create(&thread, NULL, serve, (void *)clientfd);
        printf("info: thread %ld created, serving connection fd %ld\n",
               (long)thread, clientfd);
    }
    pthread_mutex_destroy(&mutex);

    return 0;
}
