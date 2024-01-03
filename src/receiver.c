#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <assert.h>
#include "sock.h"
#include "packet.h"
#include "util.h"

int request(int receiver_fd, char *input_code);

int receive_data(int receiver_fd, char sha256_str[65]);

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

    status = request(receiver_fd, input_code);

    if (status == -1) return status;

    char sha256_str[65];
    status = receive_data(receiver_fd, sha256_str);

    info(receiver_fd, "sha256: %s", sha256_str);

    if (status == -1) return status;

    return 0;

}

int request(int receiver_fd, char *input_code)
{

    packet_header_t header;
    packet_payload_t payload;
    int status = 0;

    // request
    create_header(&header, kOpRequest, kNone, sizeof(const int));
    status = send(receiver_fd, header, HEADER_LENGTH, 0);
    free(header);
    if (status == -1) {
        error(receiver_fd, "request failed");
        return status;
    } else
        info(receiver_fd, "request success");

    // send code
    int *code = malloc(sizeof(int));
    *code = atoi(input_code);
    info(receiver_fd, "input code is %d", *code);

    create_payload(&payload, 0, GET_PAYLOAD_PACKET_LEN(sizeof(int)), (char*)code);
    status = send(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(sizeof(int)), 0);
    copy_payload(payload, (char**)&code);
    free(payload);
    if (status == -1) {
        error(receiver_fd, "send code failed");
        return status;
    } else {
        info(receiver_fd, "send code success: %d", *code);
    }

    // receive ack
    // send public key
    char *pub_key = malloc(64 * sizeof(char));
    pub_key =
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    create_payload(&payload, 0, 64, pub_key);
    status = send(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(64), 0);
    free(payload);
    if (status == -1) {
        error(receiver_fd, "send public key failed");
        return status;
    } else {
        info(receiver_fd, "send public key success");
    }
    // receive ack
    header = malloc(HEADER_LENGTH);
    status = recv(receiver_fd, header, HEADER_LENGTH, 0);
    opcode_t opcode = get_opcode(header);
    free(header);
    if (status == -1 || opcode != kOpAck) {
        error(receiver_fd, "recv ack failed");
    } else {
        info(receiver_fd, "recv ack success");
    }
    return status;
}

int receive_data(int receiver_fd, char sha256_str[65])
{
    packet_header_t header;
    packet_payload_t payload;
    int status;
    // Receive file name
    char* fname;
    payload = malloc(GET_PAYLOAD_PACKET_LEN(1024));
    status = recv(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(1024), 0);
    copy_payload(payload, &fname);
    free(payload);
    if (status == -1) {
        error(receiver_fd, "recv file name failed");
        return status;
    } else {
        info(receiver_fd, "recv file name success: %s", fname);
    }

    FILE *dst_file;
    dst_file = fopen(fname, "wb");
    if (dst_file == NULL) {
        error(receiver_fd, "Error opening destination file");
        return 1;
    } else {
        info(receiver_fd, "Open file %s successfully", fname);
    }

    // Receive data
    size_t payload_buf_len = GET_PAYLOAD_PACKET_LEN(1024);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    while (1) {
        // Receive header
        header = malloc(HEADER_LENGTH);
        status = recv(receiver_fd, header, HEADER_LENGTH, 0);
        opcode_t opcode = get_opcode(header);
        payload_type_t payload_type = get_payload_type(header);
        size_t seg_len = get_payload_length(header);
        payload_buf_len = GET_PAYLOAD_PACKET_LEN(seg_len);
        free(header);
        if (status == -1) {
            error(receiver_fd, "recv data header failed");
            return status;
        } else  if (opcode == kOpFin && payload_type == kNone) {
            info(receiver_fd, "recv end");
            break;
        } else if (opcode == kOpData && payload_type == kData) {
            info(receiver_fd, "wait for data");
        } else {
            error(receiver_fd, "recv data header failed");
            return -1;
        }

        // Receive data
        char *data_seg;
        payload = malloc(payload_buf_len);
        status = recv(receiver_fd, payload, payload_buf_len, 0);
        copy_payload(payload, &data_seg);
        free(payload);
        if (status == -1) {
            error(receiver_fd, "recv data failed");
            return status;
        } else {
            info(receiver_fd, "recv data success");
        }

        SHA256_Update(&sha256, data_seg, seg_len);

        fwrite(data_seg, sizeof(char), seg_len, dst_file);
        free(data_seg);

        // Send ack
        create_header(&header, kOpAck, kNone, 0);
        status = send(receiver_fd, header, HEADER_LENGTH, 0);
        free(header);
        if (status == -1) {
            error(receiver_fd, "send ack failed");
            return status;
        } else
            info(receiver_fd, "send ack success");

    }

    SHA256_Final(hash, &sha256);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(sha256_str + (i * 2), "%02x", hash[i]);
    }

    fclose(dst_file);
    create_header(&header, kOpFin, kNone, 0);
    status = send(receiver_fd, header, HEADER_LENGTH, 0);
    free(header);
    if (status == -1) {
        error(receiver_fd, "finish failed");
    } else {
        info(receiver_fd, "finish success");
    }
    return status;
}
