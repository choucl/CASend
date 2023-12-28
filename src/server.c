#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
#define TABLE_SIZE  256
static pthread_mutex_t mutex;

typedef enum service_status {
    kWaitingRecv,
    kWaitingSend,
} service_status_t;

typedef struct service_entry service_entry_t;

struct service_entry {
    int code;  // generated code
    int clientfd;
    int name_length;
    char *name;
    char *pub_key;
    service_status_t status;
};

int has_vacancy;
service_entry_t *service_table[TABLE_SIZE];

static int gen_code(int code_length) {
    srand(time(NULL));
    return rand() % (int)pow(10, code_length);
}

static service_entry_t *create_table_entry(int clientfd, int code_length, 
                                     char *name, int name_length) {
    int code;
    int position;
    do {
        code = gen_code(kCodeLength);
        position = code % TABLE_SIZE;
    } while(service_table[position] != NULL);
    
    service_entry_t *new_entry = malloc(sizeof(service_entry_t));
    new_entry->code = code;
    new_entry->clientfd = clientfd;
    new_entry->status = kWaitingRecv;
    new_entry->name = name;
    new_entry->name_length = name_length;
    new_entry->pub_key = NULL;

    service_table[position] = new_entry; 
    return new_entry;
}

static int send_intention_handler(service_entry_t **entry, 
                                  long clientfd, int name_length) {
    int status = 0;
    info(clientfd, "receive send intention");
    // receive name payload
    packet_payload_t recv_name_payload = 
        malloc(GET_PAYLOAD_PACKET_LEN(name_length));
    status = recv(clientfd, recv_name_payload, 
                  GET_PAYLOAD_PACKET_LEN(name_length), 0);
    if (status == -1) {
        error(clientfd, "recv name payload.");
        goto SEND_INTENTION_RET;
    }
    char *name;
    if (copy_payload(recv_name_payload, &name) == -1 || name[0] == 0) {
        error(clientfd, "parsing name.")
        goto SEND_INTENTION_RET;
    }
    info(clientfd, "name payload received - %s", name);
    
    pthread_mutex_lock(&mutex);
    *entry = create_table_entry(clientfd, kCodeLength, name, name_length);
    pthread_mutex_unlock(&mutex);
    info(clientfd, "entry creation complete, code = %d", (*entry)->code);
    free(recv_name_payload);
    
    // send code header
    info(clientfd, "sending ack header");
    packet_header_t send_header;
    create_header(&send_header, kOpAck, kCode, sizeof(const int));
    send(clientfd, send_header, HEADER_LENGTH, 0);
    
    // send code payload
    info(clientfd, "sending code payload");
    packet_payload_t send_code_payload;
    status = create_payload(&send_code_payload, 0, sizeof(const int),
                            (char *)&(*entry)->code);
    if (status == -1) {
        error(clientfd, "fail creating code payload");
        goto SEND_INTENTION_RET;
    }
    send(clientfd, send_code_payload, 
         GET_PAYLOAD_PACKET_LEN(sizeof(const int)), 0);
SEND_INTENTION_RET:
    return status;
}

static int send_pub_key_handler(long clientfd, service_entry_t *entry) {
    int status = 0;
    packet_header_t send_pub_key_header;
    if (create_header(&send_pub_key_header, kOpPub, kPubKey, 64) == -1) {
        error(clientfd, "fail creating pub-key header");
        return -1;
    }
    send(clientfd, send_pub_key_header, HEADER_LENGTH, 0);

    packet_payload_t send_pub_key_payload;
    int packet_length = create_payload(&send_pub_key_payload, 0, 
                                       64, entry->pub_key);
    if (packet_length == -1) {
        error(clientfd, "fail creating pub-key payload")
        return -1;
    }
    send(clientfd, send_pub_key_payload, packet_length, 0);
    free(send_pub_key_payload);
    
    // wait sender ack
    packet_payload_t recv_ack_header = malloc(HEADER_LENGTH);
    status = recv(clientfd, recv_ack_header, HEADER_LENGTH, 0);
    if (status == -1) {
        error(clientfd, "receive ack pubkey ack failed");
    } else if (status == 0) {
        error(clientfd, "receiver disconnected");
        status = -1;
    } else if (get_opcode(recv_ack_header) != kOpAck) {
        error(clientfd, "wrong opcode");
        status = -1;
    }
    free(recv_ack_header);
    return status;
}

static int receiver_request_handler(service_entry_t **entry, long clientfd) {
    info(clientfd, "receive request intention");
    int status = 0;
    // receive code
    packet_payload_t recv_code_payload = 
        malloc(GET_PAYLOAD_PACKET_LEN(sizeof(int)));
    status = recv(clientfd, recv_code_payload,
                  GET_PAYLOAD_PACKET_LEN(sizeof(int)), 0);
    if (status == -1) {
        error(clientfd, "fail receiving code payload");
        goto REQ_ERR_RET0;
    }
    int *recv_code;
    copy_payload(recv_code_payload, (char **)&recv_code);
    info(clientfd, "recv code payload = %d");
    
    // receive public key
    packet_payload_t recv_pubkey_payload = 
        malloc(GET_PAYLOAD_PACKET_LEN(64));
    status = recv(clientfd, recv_pubkey_payload, GET_PAYLOAD_PACKET_LEN(64), 0);
    if (status == -1) {
        error(clientfd, "recv code payload");
        goto REQ_ERR_RET1;
    }
    char *pub_key;
    copy_payload(recv_pubkey_payload, &pub_key);
    info(clientfd, "recv pub_key payload = %s", pub_key);
    
    *entry = service_table[(*recv_code) % TABLE_SIZE];
    packet_header_t send_ack_header;
    if (*entry) {  // entry found
        (*entry)->pub_key = pub_key;
        status = create_header(&send_ack_header, kOpAck, kNone, 0);
        if (status == -1) {
            error(clientfd, "fail creating ack header");
            goto REQ_ERR_RET1;
        }
        send(clientfd, send_ack_header, HEADER_LENGTH, 0);

        packet_payload_t send_name_payload;
        int payload_len = create_payload(&send_name_payload, 0, 
                                         (*entry)->name_length, (*entry)->name);
        if ((status = payload_len) == -1) {
            error(clientfd, "fail creating name payload");
            goto REQ_ERR_RET1;
        }
        send(clientfd, send_name_payload, payload_len, 0);
        free(send_name_payload);
    } else {  // entry not found
        status = create_header(&send_ack_header, kOpError, kNone, 0);
        if (status == -1) {
            error(clientfd, "fail creating ack header");
            goto REQ_ERR_RET1;
        }
        send(clientfd, send_ack_header, HEADER_LENGTH, 0);
        error(clientfd, "recv code not found");
        status = -1;
    }
    free(send_ack_header);
REQ_ERR_RET1:
    free(recv_pubkey_payload);
REQ_ERR_RET0:
    free(recv_code_payload);
    return status;
}

int send_data_handler(long clientfd) {
    int status = 0;
    int payload_buf_len = GET_PAYLOAD_PACKET_LEN(1024);
    packet_header_t recv_data_header = malloc(HEADER_LENGTH);
    packet_payload_t recv_data_payload = malloc(payload_buf_len);
    packet_header_t recv_ack_header = malloc(HEADER_LENGTH);
    packet_header_t send_ack_header;
    status = create_header(&send_ack_header, kOpAck, kNone, 0);
    if (status == -1) {
        error(clientfd, "fail creating data ack");
        return -1;
    }
    while (1) {
        status = recv(clientfd, recv_data_header, HEADER_LENGTH, 0);
        if (status == -1) {
            error(clientfd, "fail receiving data header");
            break;
        }
        if (get_opcode(recv_data_header) == kOpData) {
            int payload_len = recv(clientfd, recv_data_payload, 
                                   payload_buf_len, 0);
            if (payload_len == -1) {
                error(clientfd, "fail receiving data payload");
                break;
            }
            send(clientfd, recv_data_header, HEADER_LENGTH, 0);
            send(clientfd, recv_data_payload, payload_len, 0);
            
            status = recv(clientfd, recv_ack_header, HEADER_LENGTH, 0);
            if (status == -1 || get_opcode(recv_ack_header) != kOpAck) {
                error(clientfd, "fail receiving data ack");
                break;
            }
            send(clientfd, send_ack_header, HEADER_LENGTH, 0);
        } else if (get_opcode(recv_data_header) == kOpFin) {
            info(clientfd, "data sending done");
            break;
        }
    }
    free(recv_data_header);
    free(recv_data_payload);
    free(recv_ack_header);
    return status;
}

int send_data_ack_handler(long clientfd) {
    int status = 0;
    packet_header_t recv_ack_header = malloc(HEADER_LENGTH);
    while (1) {
        status = recv(clientfd, recv_ack_header, HEADER_LENGTH, 0);
        if (status == -1) {
            error(clientfd, "fail receiving ack header");
            break;
        }
        opcode_t recv_opcode = get_opcode(recv_ack_header);
        if (recv_opcode == kOpAck || recv_opcode == kOpFin) {
            send(clientfd, recv_ack_header, HEADER_LENGTH, 0);
            if (recv_opcode == kOpFin)
                break;
        } else {
            error(clientfd, "header opcode not ack, %d", recv_opcode);
            break;
        }
    }
    free(recv_ack_header);
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
        error(clientfd, "invalid packet header");
        return 0;
    }
    if (get_opcode(recv_header) == kOpCreate) {  // sender request
        
        // handler send file intention
        service_entry_t *working_entry;
        status = send_intention_handler(&working_entry, clientfd, 
                                        get_payload_length(recv_header));
        if (status == -1) {
            error(clientfd, "handle sender intention failed");
            return 0;
        }
        
        // wait until receiver public key delivered
        while (working_entry->pub_key == NULL);
        status = send_pub_key_handler(clientfd, working_entry);
        if (status == -1) {
            error(clientfd, "handle pubkey intention failed");
            return 0;
        }
                
        // send data from sender
        status = send_data_handler(clientfd);
        if (status == -1) {
            error(clientfd, "handle data sending failed");
            return 0;
        }
    } else if (get_opcode(recv_header) == kOpRequest) {  // receiver request
        service_entry_t *working_entry;
        status = receiver_request_handler(&working_entry, clientfd);
        if (status == -1) {
            error(clientfd, "handle receive intention failed");
            return 0;
        }

        // receive data and ack
        status = send_data_ack_handler(clientfd);
        if (status == -1) {
            error(clientfd, "handle ack sending failed");
            return 0;
        }

        int code = working_entry->code;
        free(working_entry);
        service_table[code % TABLE_SIZE] = NULL;
    } else {  // invalid situation
        error(clientfd, "invalid header opcode", get_opcode(recv_header));
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
    for (int i = 0; i < TABLE_SIZE; ++i) {
        service_table[i] = NULL;
    }
    while (1) {
        struct sockaddr client_info;
        socklen_t addrlen;
        long clientfd = accept(listenfd, &client_info, &addrlen);
        if (clientfd == -1) continue;
        pthread_t thread;
        pthread_create(&thread, NULL, serve, (void *)clientfd);
        info(clientfd, "serving thread %ld created", (long)thread);
    }
    pthread_mutex_destroy(&mutex);

    return 0;
}
