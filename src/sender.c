#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sock.h"
#include "packet.h"

int send_intention(int sender_fd, packet_header_t *header,
                            packet_payload_t *payload, char *fname);

int receive_pub_key(int sender_fd, packet_header_t *header,
                    packet_payload_t *payload, char *fname, char **pub_key);

int send_data(int sender_fd, packet_header_t *header,
                        packet_payload_t *payload, char *fname, char *pub_key);

int main(int argc, char *argv[])
{
    char *host = NULL, *port = NULL, *fname = NULL;

    if (argc != 7) {
        printf("Usage: ./client -i server_ip -p server_port -f file_name\n");
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
    if (argc > 0 && **argv == '-' && (*argv)[1] == 'f') {
        --argc; ++argv;
        if (argc < 1)
            return -1;
        fname = malloc(sizeof(char) * strlen(*argv) + 1);
        strncpy(fname, *argv, strlen(*argv));
    }



    if (host == NULL || port == NULL) {
        printf("[Error] Server host or port not specified. Exit game.\n");
        exit(-1);
    } else {
        printf("[Info] Input host: %s, port: %s\n", host, port);
    }

    int sender_fd __attribute__((unused)) = open_clientfd(host, port);
    if (sender_fd == -1) {
        printf("[Error] Client file descriptor open failed.\n");
        printf("[Error] Please check host and port again.\n");
        exit(-1);
    } else {
        printf("[Info] Connection established, sender_fd = %d\n", sender_fd);
    }

    // Main process
    int status = 0;
    packet_header_t sender_header;
    packet_payload_t sender_payload;

    status = send_intention(sender_fd, &sender_header, &sender_payload, fname);

    if (status == -1) return status;

    char *pub_key;
    status = receive_pub_key(sender_fd, &sender_header, &sender_payload, fname, &pub_key);

    if (status == -1) return status;

    printf("Get public key: %s\n", pub_key);

    send_data(sender_fd, &sender_header, &sender_payload, fname, pub_key);

    if (status == -1) return status;

    return 0;

}

int send_intention(int sender_fd, packet_header_t *header,
                            packet_payload_t *payload, char *fname)
{
    int status;
    // Sender send request header
    size_t name_length = strlen(fname);
    create_header(header, kOpCreate, kNone, name_length);
    status = send(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        printf("Sender request failed\n");
        return status;
    } else
        printf("Sender request success\n");

    // Sender send file name
    create_payload(payload, 0, name_length, fname); //
    char *fname_copy;
    copy_payload(*payload, &fname_copy);
    status = send(sender_fd, *payload, GET_PAYLOAD_PACKET_LEN(name_length), 0);
    if (status == -1) {
        printf("Sender send file name failed\n");
        return status;
    } else
        printf("Sender send file name success: %s\n", fname_copy);

    // Sender get acknowledgement
    *header = malloc(HEADER_LENGTH);
    status = recv(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        printf("Sender recv ack failed\n");
        return status;
    } else
        printf("Sender recv ack success\n");

    // Sender get code
    int* code;
    *payload = malloc(GET_PAYLOAD_PACKET_LEN(sizeof(const int)));
    status = recv(sender_fd, *payload, GET_PAYLOAD_PACKET_LEN(sizeof(const int)), 0);
    if (status == -1)
        printf("Sender recv code failed\n");
    else {
        copy_payload(*payload, (char**)&code);
        printf("Sender recv code success: %d\n", *code);
    }

    return status;
}

int receive_pub_key(int sender_fd, packet_header_t *header,
                    packet_payload_t *payload, char *fname, char **pub_key)
{
    int status;
    // Sender recv public key header
    *header = malloc(HEADER_LENGTH);
    status = recv(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        printf("Sender recv public key header failed\n");
        return status;
    } else {
        printf("Sender recv public key header success\n");
    }

    // Sender recv public key
    *payload = malloc(GET_PAYLOAD_PACKET_LEN(64));
    status = recv(sender_fd, *payload, GET_PAYLOAD_PACKET_LEN(64), 0);
    if (status == -1) {
        printf("Sender recv public key failed\n");
        return status;
    } else {
        copy_payload(*payload, pub_key);
        printf("Sender recv public key success: %s\n", *pub_key);
    }

    // Sender ack public key
    create_header(header, kOpAck, kPubKey, 0);
    status = send(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Sender ack public key failed\n");
    else
        printf("Sender ack public key success\n");

    return status;
}

int send_data(int sender_fd, packet_header_t *header,
                        packet_payload_t *payload, char *fname, char *pub_key)
{
    FILE *src_file;
    src_file = fopen(fname, "rb");

    if (src_file == NULL) {
        printf("Error opening source file\n");
        return 1;
    } else {
        printf("Open file %s successfully\n", fname);
    }

    size_t data_size = 1024;
    char *data = malloc(data_size * sizeof(char));
    int status;

    // Read data & send
    while (fread(data, data_size, 1, src_file)) {
        // Send data header
        create_header(header, kOpData, kData, data_size);
        status = send(sender_fd, *header, HEADER_LENGTH, 0);
        if (status == -1) {
            printf("Sender send data header failed\n");
            return status;
        } else
            printf("Sender send data header success\n");

        //  Send data paylaod
        int payload_size = create_payload(payload, 0, data_size, data);
        char *data_copy;
        copy_payload(*payload, &data_copy);
        printf("payload with size %d: %s", payload_size, data_copy);
        status = send(sender_fd, *payload, GET_PAYLOAD_PACKET_LEN(data_size), 0);
        if (status == -1) {
            printf("Sender send data failed\n");
            return status;
        } else
            printf("Sender send data success\n");

        //  Receive ack
        *header = malloc(HEADER_LENGTH);
        status = recv(sender_fd, *header, HEADER_LENGTH, 0);
        if (status == -1) {
            printf("Sender recv ack failed\n");
            return status;
        } else
            printf("Sender recv ack success\n");
    }

    // End of data transfer
    fclose(src_file);

    // Send finish header
    create_header(header, kOpFin, kNone, 0);
    status = send(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        printf("Sender end sending failed\n");
        return status;
    } else
        printf("Sender end sending success\n");

    // Receive finish ack
    *header = malloc(HEADER_LENGTH);
    status = recv(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1)
        printf("Sender finish failed\n");
    else
        printf("Sender finish success\n");

    return status;
}
