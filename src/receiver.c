#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sock.h"
#include "packet.h"

int request(int receiver_fd, packet_header_t *header,
            packet_payload_t *payload, char *input_code);

int receive_data(int receiver_fd, packet_header_t *header,
            packet_payload_t *payload);

int main(int argc, char *argv[])
{
    char *host = NULL, *port = NULL, *input_code = NULL;

    if (argc != 7) {
        printf("Usage: ./client -i server_ip -p server_port -c input_code\n");
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
    if (argc > 0 && **argv == '-' && (*argv)[1] == 'c') {
        --argc; ++argv;
        if (argc < 1)
            return -1;
        input_code = malloc(sizeof(char) * strlen(*argv) + 1);
        strncpy(input_code, *argv, strlen(*argv));
    }

    if (host == NULL || port == NULL) {
        printf("[Error] Server host or port not specified. Exit game.\n");
        exit(-1);
    } else {
        printf("[Info] Input host: %s, port: %s\n", host, port);
    }

    int receiver_fd __attribute__((unused)) = open_clientfd(host, port);
    if (receiver_fd == -1) {
        printf("[Error] Client file descriptor open failed.\n");
        printf("[Error] Please check host and port again.\n");
        exit(-1);
    } else {
        printf("[Info] Connection established, receiver_fd = %d\n", receiver_fd);
    }

    // Main process
    int status = 0;

    packet_header_t receiver_header;
    packet_payload_t receiver_payload;

    status = request(receiver_fd, &receiver_header, &receiver_payload, input_code);

    if (status == -1) return status;

    status = receive_data(receiver_fd, &receiver_header, &receiver_payload);

    if (status == -1) return status;

    return 0;

}

int request(int receiver_fd, packet_header_t *header,
            packet_payload_t *payload, char *input_code)
{
    int status = 0;

    // Receiver request
    create_header(header, kOpRequest, kNone, sizeof(const int));
    status = send(receiver_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        printf("Receiver request failed\n");
        return status;
    } else
        printf("Receiver request success\n");

    // Receiver send code
    int *code = malloc(sizeof(int));
    *code = atoi(input_code);
    printf("Your input code is %d\n", *code);

    create_payload(payload, 0, GET_PAYLOAD_PACKET_LEN(sizeof(int)), (char*)code);
    status = send(receiver_fd, *payload, GET_PAYLOAD_PACKET_LEN(sizeof(int)), 0);
    if (status == -1) {
        printf("Receiver send code failed\n");
        return status;
    } else {
        copy_payload(*payload, (char**)&code);
        printf("Receiver send code success: %d\n", *code);
    }

    // Receiver send public key
    char *pub_key = malloc(64 * sizeof(char));
    pub_key =
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    create_payload(payload, 0, 64, pub_key);
    status = send(receiver_fd, *payload, GET_PAYLOAD_PACKET_LEN(64), 0);
    if (status == -1) {
        printf("Receiver send public key failed\n");
        return status;
    } else
        printf("Receiver send public key success\n");
    // Receiver receive ack
    *header = malloc(HEADER_LENGTH);
    status = recv(receiver_fd, *header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Receiver recv ack failed\n");
    else
        printf("Receiver recv ack success\n");

    return status;
}

int receive_data(int receiver_fd, packet_header_t *header,
            packet_payload_t *payload)
{
    int status;


    // Receive file name
    char* fname;
    *payload = malloc(GET_PAYLOAD_PACKET_LEN(1024));
    status = recv(receiver_fd, *payload, GET_PAYLOAD_PACKET_LEN(1024), 0);
    if (status == -1) {
        printf("Receiver recv file name failed\n");
        return status;
    } else {
        copy_payload(*payload, &fname);
        printf("Receiver recv file name success: %s\n", fname);
    }

    FILE *dst_file;
    dst_file = fopen(fname, "wb");
    if (dst_file == NULL) {
        printf("Error opening destination file\n");
        return 1;
    } else {
        printf("Open file %s successfully\n", fname);
    }

    // Receive data
    char* data;
    int payload_buf_len = GET_PAYLOAD_PACKET_LEN(1024);

    while (1) {
        // Receive header
        *header = malloc(HEADER_LENGTH);
        status = recv(receiver_fd, *header, HEADER_LENGTH, 0);
        if (status == -1) {
            printf("Receiver recv data header failed\n");
            return status;
        } else
            printf("Receiver recv data header success\n");

        if (get_opcode(*header) == kOpFin) {
            printf("Receiver recv end\n");
            break;
        } else {
            printf("Receiver wait for data\n");
        }

        // Receive data
        *payload = malloc(payload_buf_len);
        status = recv(receiver_fd, *payload, payload_buf_len, 0);
        if (status == -1) {
            printf("Receiver recv data failed\n");
            return status;
        } else {
            copy_payload(*payload, &data);
            printf("Receiver recv data success: %s", data);
        }

        // Write data to file
        fwrite(data, 1024, 1, dst_file);

        // Send ack
        create_header(header, kOpAck, kNone, 0);
        status = send(receiver_fd, *header, HEADER_LENGTH, 0);
        if (status == -1) {
            printf("Receiver send ack failed\n");
            return status;
        } else
            printf("Receiver send ack success\n");

    }

    fclose(dst_file);
    create_header(header, kOpFin, kNone, 0);
    status = send(receiver_fd, *header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Receiver finish failed\n");
    else
        printf("Receiver finish success\n");

    return status;
}
