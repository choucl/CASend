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
    create_payload(&sender_payload, 0, name_length, file_name);
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

    // 6. Sender recv public key
    sender_payload = malloc(GET_PAYLOAD_PACKET_LEN(64));
    status = recv(client_fd, sender_payload, GET_PAYLOAD_PACKET_LEN(64), 0);
    char* pub_key;
    if (status == -1)
        printf("Sender recv public key failed\n");
    else {
        copy_payload(sender_payload, &pub_key);
        printf("Sender recv public key success: %s\n", pub_key);
    }

    // 7. Sender ack public key
    create_header(&sender_header, kOpAck, kPubKey, 0);
    status = send(client_fd, sender_header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Sender ack public key failed\n");
    else
        printf("Sender ack public key success\n");

    // 8. Sender send data
    //  First data
    //  Send header
    create_header(&sender_header, kOpData, kData, 8);
    status = send(client_fd, sender_header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Sender send data 0 header failed\n");
    else
        printf("Sender send data 0 header success\n");
    //  Send data
    char *data = malloc(8 * sizeof(char));
    data = "qwerqwer";
    create_payload(&sender_payload, 0, 8, data);
    status = send(client_fd, &sender_payload, GET_PAYLOAD_PACKET_LEN(8), 0);
    if (status == -1)
        printf("Sender send data 0 failed\n");
    else
        printf("Sender send data 0 success\n");
    //  Recv ack
    sender_header = malloc(HEADER_LENGTH);
    status = recv(client_fd, sender_header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Sender recv ack 0 failed\n");
    else
        printf("Sender recv ack 0 success\n");
    // Second data
    //  Send header
    create_header(&sender_header, kOpData, kData, 8);
    status = send(client_fd, sender_header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Sender send data 1 header failed\n");
    else
        printf("Sender send data 1 header success\n");
    //  Send data
    data = "asdfasdf";
    create_payload(&sender_payload, 0, 8, data);
    status = send(client_fd, &sender_payload, GET_PAYLOAD_PACKET_LEN(8), 0);
    if (status == -1)
        printf("Sender send data 1 failed\n");
    else
        printf("Sender send data 1 success\n");
    //  Recv ack
    sender_header = malloc(HEADER_LENGTH);
    status = recv(client_fd, sender_header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Sender recv ack 1 failed\n");
    else
        printf("Sender recv ack 1 success\n");
    // 9. Sender ends sending
    create_header(&sender_header, kOpFin, kNone, 0);
    status = send(client_fd, sender_header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Sender end sending failed\n");
    else
        printf("Sender end sending success\n");

    return 0;

}
