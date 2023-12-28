#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sock.h"
#include "packet.h"


int main(int argc, char *argv[])
{
    char *host = NULL, *port = NULL;

    int is_sender = 0;

    if (argc != 6) {
        printf("Usage: ./client -i server_ip -p server_port\n");
        return -1;
    }

    --argc; ++argv;
    if (argc > 0 && **argv == '-' && (*argv)[1] == 'i') {
        --argc; ++argv;
        if (argc < 1)
            return -1;
        host = malloc(sizeof(char) * strlen(*argv) + 1);
        strncpy(host, *argv, strlen(*argv));
    }

    --argc; ++argv;
    if (argc > 0 && **argv == '-' && (*argv)[1] == 'p') {
        --argc; ++argv;
        if (argc < 1)
            return -1;
        port = malloc(sizeof(char) * strlen(*argv) + 1);
        strncpy(port, *argv, strlen(*argv));
    }

    --argc; ++argv;
    if (argc > 0 && **argv == '-' && (*argv)[1] == 's') { // sender
        //--argc; ++argv;
        //if (argc < 1)
        //    return -1;
        is_sender = 1;
        printf("Build sender\n");
    } else if (argc > 0 && **argv == '-' && (*argv)[1] == 'r') { // sender
        //--argc; ++argv;
        //if (argc < 1)
        //    return -1;
        is_sender = 0;
        printf("Build receiver\n");
    } else {
        printf("Build ?\n");
    }

    if (host == NULL || port == NULL) {
        printf("[Error] Server host or port not specified. Exit game.\n");
        exit(-1);
    } else {
        printf("[Info] Input host: %s, port: %s\n", host, port);
    }

    int client_fd __attribute__((unused)) = open_clientfd(host, port);
    if (client_fd == -1) {
        printf("[Error] Client file descriptor open failed.\n");
        printf("[Error] Please check host and port again.\n");
        exit(-1);
    } else {
        printf("[Info] Connection established, client_fd = %d\n", client_fd);
    }

    // Test server
    int status = 0;

    if (is_sender == 1) {
        packet_header_t sender_header;
        packet_payload_t sender_payload;
        size_t name_length = 7;
        char *file_name = malloc(name_length * sizeof(char));
        file_name = "bar.log";
        printf("file name is %s\n", file_name);
        // 1. Sender requests
        create_header(&sender_header, kOpCreate, kNone, name_length*sizeof(char));
        status = send(client_fd, sender_header, HEADER_LENGTH, 0);
        if (status == -1)
            printf("Sender request failed\n");
        else
            printf("Sender request success\n");
        // 2. Sender send file name
        int size = create_payload(&sender_payload, 0, name_length, file_name);
        status = send(client_fd, sender_payload, GET_PAYLOAD_PACKET_LEN(name_length), 0);
        if (status == -1)
            printf("Sender send file name failed\n");
        else
            printf("Sender send file name success\n");
        // 3. Sender get acknowledgement
        sender_header= malloc(HEADER_LENGTH + 1);
        status = recv(client_fd, sender_header, HEADER_LENGTH, 0);
        if (status == -1)
            printf("Sender recv ack failed\n");
        else
            printf("Sender recv ack success\n");
        // 4. Sender get code
        int* code;
        sender_payload = malloc(GET_PAYLOAD_PACKET_LEN(sizeof(const int)));
        status = recv(client_fd, sender_payload, GET_PAYLOAD_PACKET_LEN(sizeof(const int)), 0);
        if (status == -1)
            printf("Sender recv code failed\n");
        else {
            copy_payload(sender_payload, (char**)&code);
            printf("Sender recv code success: %d\n", *code);
        }
        // 5. Sender recv public key header
        sender_header = malloc(HEADER_LENGTH);
        status = recv(client_fd, sender_header, HEADER_LENGTH, 0);
        if (status == -1)
            printf("Sender recv public key header failed\n");
        else {
            printf("Sender recv public key header success\n");
        }
        // 6 Sender recv public key
        sender_payload = malloc(GET_PAYLOAD_PACKET_LEN(64));
        status = recv(client_fd, sender_payload, GET_PAYLOAD_PACKET_LEN(64), 0);
        char* pub_key;
        if (status == -1)
            printf("Sender recv public key failed\n");
        else {
            copy_payload(sender_payload, &pub_key);
            printf("Sender recv public key success: %s\n", pub_key);
        }
        // 6. Sender ack public key
        create_header(&sender_header, kOpAck, kPubKey, 0);
        status = send(client_fd, sender_header, HEADER_LENGTH, 0);
        if (status == -1)
            printf("Sender ack public key failed\n");
        else
            printf("Sender ack public key success\n");
    } else {
        packet_header_t receiver_header;
        packet_payload_t receiver_payload;
        // 1. Receiver request
        create_header(&receiver_header, kOpRequest, kNone, sizeof(const int));
        status = send(client_fd, receiver_header, HEADER_LENGTH, 0);
        if (status == -1)
            printf("Receiver request failed\n");
        else {
            printf("Receiver request success\n");
        }
        // 2. Receiver send code
        int* code = malloc(sizeof(int));
        printf("Input code:");
        scanf("%d", code);
        printf("Your input is %d\n", *code);

        create_payload(&receiver_payload, 0, GET_PAYLOAD_PACKET_LEN(sizeof(int)), (char*) code);
        status = send(client_fd, receiver_payload, GET_PAYLOAD_PACKET_LEN(sizeof(int)), 0);
        if (status == -1)
            printf("Receiver send code failed\n");
        else {
            copy_payload(receiver_payload, (char**)&code);
            printf("Receiver send code success: %d\n", *code);
        }
        // 3. Receiver send public key
        char* pub_key = malloc(64 * sizeof(char));
        pub_key = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        create_payload(&receiver_payload, 0, 64, pub_key);
        status = send(client_fd, receiver_payload, GET_PAYLOAD_PACKET_LEN(64), 0);
        if (status == -1)
            printf("Receiver send public key failed\n");
        else
            printf("Receiver send public key success\n");
        // 4. Receiver recv ack
        receiver_header = malloc(HEADER_LENGTH);
        status = recv(client_fd, receiver_header, HEADER_LENGTH, 0);
        if (status == -1)
            printf("Receiver recv ack failed\n");
        else
            printf("Receiver recv ack success\n");

    }
    return 0;

}
