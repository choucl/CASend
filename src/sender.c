#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "sock.h"
#include "packet.h"
#include "util.h"

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

    info(sender_fd, "Get public key: %s", pub_key);

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
        error(sender_fd, "Sender request failed");
        return status;
    } else
        info(sender_fd, "Sender request success");

    // Sender send file name
    create_payload(payload, 0, name_length, fname); //
    char *fname_copy;
    copy_payload(*payload, &fname_copy);
    status = send(sender_fd, *payload, GET_PAYLOAD_PACKET_LEN(name_length), 0);
    if (status == -1) {
        error(sender_fd, "Sender send file name failed");
        return status;
    } else
        info(sender_fd, "Sender send file name success: %s", fname_copy);

    // Sender get acknowledgement
    *header = malloc(HEADER_LENGTH);
    status = recv(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        error(sender_fd, "Sender recv ack failed");
        return status;
    } else
        info(sender_fd, "Sender recv ack success");

    // Sender get code
    int* code;
    *payload = malloc(GET_PAYLOAD_PACKET_LEN(sizeof(const int)));
    status = recv(sender_fd, *payload, GET_PAYLOAD_PACKET_LEN(sizeof(const int)), 0);
    if (status == -1) {
        error(sender_fd, "Sender recv code failed");
    } else {
        copy_payload(*payload, (char**)&code);
        info(sender_fd, "Sender recv code success: %d", *code);
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
        error(sender_fd, "Sender recv public key header failed");
        return status;
    } else {
        info(sender_fd, "Sender recv public key header success");
    }

    // Sender recv public key
    *payload = malloc(GET_PAYLOAD_PACKET_LEN(64));
    status = recv(sender_fd, *payload, GET_PAYLOAD_PACKET_LEN(64), 0);
    if (status == -1) {
        error(sender_fd, "Sender recv public key failed");
        return status;
    } else {
        copy_payload(*payload, pub_key);
        info(sender_fd, "Sender recv public key success: %s", *pub_key);
    }

    // Sender ack public key
    create_header(header, kOpAck, kPubKey, 0);
    status = send(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        error(sender_fd, "Sender ack public key failed");
    } else {
        info(sender_fd, "Sender ack public key success");
    }
    return status;
}

int send_data(int sender_fd, packet_header_t *header,
                        packet_payload_t *payload, char *fname, char *pub_key)
{
    FILE *src_file;
    src_file = fopen(fname, "rb");

    if (src_file == NULL) {
        error(sender_fd, "Error opening source file");
        return 1;
    } else {
        info(sender_fd, "Open file %s successfully", fname);
    }

    size_t chunk_size = 1024;
    char *data_chunk = malloc(chunk_size * sizeof(char));
    int status;
    int final_chunk = 0;
    size_t payload_length;

    // Read data & send
    while (1) {

        payload_length = fread(data_chunk, sizeof(char), chunk_size, src_file);

        if (payload_length < chunk_size) {
            chunk_size = payload_length;
            final_chunk = 1;
            //info(sender_fd, "Last chunk size %ld", payload_length);
        } //else {
            //info(sender_fd, "Chunk size %ld", payload_length);
        //}

        // Send data header
        create_header(header, kOpData, kData, chunk_size);
        status = send(sender_fd, *header, HEADER_LENGTH, 0);
        if (status == -1) {
            error(sender_fd, "Sender send data header failed");
            return status;
        } else
            info(sender_fd, "Sender send data header success");

        //  Send data paylaod
        create_payload(payload, 0, chunk_size, data_chunk);
        status = send(sender_fd, *payload, GET_PAYLOAD_PACKET_LEN(chunk_size), 0);
        if (status == -1) {
            error(sender_fd, "Sender send data failed");
            return status;
        } else
            info(sender_fd, "Sender send data success");

        //  Receive ack
        *header = malloc(HEADER_LENGTH);
        status = recv(sender_fd, *header, HEADER_LENGTH, 0);
        if (status == -1) {
            error(sender_fd, "Sender recv ack failed");
            return status;
        } else
            info(sender_fd, "Sender recv ack success");

        if (final_chunk) break;
    }

    // End of data transfer
    fclose(src_file);

    // Send finish header
    create_header(header, kOpFin, kNone, 0);
    status = send(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        error(sender_fd, "Sender end sending failed");
        return status;
    } else
        info(sender_fd, "Sender end sending success");

    // Receive finish ack
    *header = malloc(HEADER_LENGTH);
    status = recv(sender_fd, *header, HEADER_LENGTH, 0);
    if (status == -1) {
        error(sender_fd, "Sender finish failed");
    } else {
        info(sender_fd, "Sender finish success");
    }
    return status;
}
