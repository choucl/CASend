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

    if (argc != 5) {
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
    // 5. Receiver recv file name
    char* fname;
    receiver_payload = malloc(GET_PAYLOAD_PACKET_LEN(1024));
    status = recv(client_fd, receiver_payload, GET_PAYLOAD_PACKET_LEN(1024), 0);
    if (status == -1)
        printf("Receiver recv file name failed\n");
    else {
        copy_payload(receiver_payload, &fname);
        printf("Receiver recv file name success: %s\n", fname);
    }

    // 6. Receiver recv data
    char* data;
    int payload_buf_len = GET_PAYLOAD_PACKET_LEN(1024);
    while (1) {
        // Recv header
        receiver_header = malloc(HEADER_LENGTH);
        status = recv(client_fd, receiver_header, HEADER_LENGTH, 0);
        if (status == -1)
            printf("Receiver recv data header failed\n");
        else
            printf("Receiver recv data header success\n");

        if (get_opcode(receiver_header) == kOpFin) {
            printf("Receiver recv end\n");
            break;
        } else {
            printf("Receiver wait for data\n");
        }

        // Recv data
        receiver_payload = malloc(payload_buf_len);
        status = recv(client_fd, receiver_payload, payload_buf_len, 0);
        if (status == -1)
            printf("Receiver recv data failed\n");
        else {
            copy_payload(receiver_payload, &data);
            printf("Receiver recv data success: %s\n", data);
        }
        // Send ack
        create_header(&receiver_header, kOpAck, kNone, 0);
        status = send(client_fd, receiver_header, HEADER_LENGTH, 0);
        if (status == -1)
            printf("Receiver send ack failed\n");
        else
            printf("Receiver send ack success\n");

    }

    return 0;

}
