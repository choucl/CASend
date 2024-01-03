#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include "sock.h"
#include "packet.h"
#include "util.h"

int send_intention(int sender_fd, char *fname);

int receive_pub_key(int sender_fd, char *fname, char **pub_key);

int send_data(int sender_fd, char *fname, char *pub_key, char sha256_str[65]);

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

    status = send_intention(sender_fd, fname);

    if (status == -1) return status;

    char *pub_key;
    status = receive_pub_key(sender_fd, fname, &pub_key);

    if (status == -1) return status;

    info(sender_fd, "Get public key: %s", pub_key);

    char sha256_str[65];

    send_data(sender_fd, fname, pub_key, sha256_str);
    info(sender_fd, "sha256: %s", sha256_str);

    if (status == -1) return status;

    return 0;

}

int send_intention(int sender_fd, char *fname)
{
    packet_header_t header;
    packet_payload_t payload;
    int status;
    // send request header
    size_t name_length = strlen(fname);
    create_header(&header, kOpCreate, kData, name_length);
    create_payload(&payload, 0, name_length, fname);
    status = send(sender_fd, header, HEADER_LENGTH, 0);
    free(header);
    if (status == -1) {
        error(sender_fd, "request failed");
        return status;
    } else {
        info(sender_fd, "request success");
    }

    // send file name
    status = send(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(name_length), 0);
    free(payload);
    if (status == -1) {
        error(sender_fd, "send file name failed");
        return status;
    } else {
        info(sender_fd, "send file name success: %s", fname);
    }

    // get acknowledgement
    header = malloc(HEADER_LENGTH);
    status = recv(sender_fd, header, HEADER_LENGTH, 0);
    opcode_t opcode = get_opcode(header);
    payload_type_t payload_type = get_payload_type(header);
    free(header);
    if (status == -1 || opcode != kOpAck || payload_type != kCode) {
        error(sender_fd, "recv ack failed");
        return status;
    } else {
        info(sender_fd, "recv ack success");
    }

    // get code
    int* code;
    size_t code_payload_length = GET_PAYLOAD_PACKET_LEN(sizeof(const int));
    payload = malloc(code_payload_length);
    status = recv(sender_fd, payload, code_payload_length, 0);
    if (status == -1) {
        error(sender_fd, "recv code failed");
    } else {
        copy_payload(payload, (char**)&code);
        info(sender_fd, "recv code success: %d", *code);
    }
    free(payload);

    return status;
}

int receive_pub_key(int sender_fd, char *fname, char **pub_key)
{
    int status;
    // recv public key header
    packet_header_t header = malloc(HEADER_LENGTH);
    packet_payload_t payload = malloc(GET_PAYLOAD_PACKET_LEN(64));
    status = recv(sender_fd, header, HEADER_LENGTH, 0);
    opcode_t opcode = get_opcode(header);
    payload_type_t payload_type = get_payload_type(header);
    free(header);
    if (status == -1 || opcode != kOpPub || payload_type != kPubKey) {
        error(sender_fd, "recv public key header failed");
        return status;
    } else {
        info(sender_fd, "recv public key header success");
    }

    // recv public key
    status = recv(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(64), 0);

    copy_payload(payload, pub_key);
    free(payload);
    if (status == -1) {
        error(sender_fd, "recv public key failed");
        return status;
    } else {
        info(sender_fd, "recv public key success: %s", *pub_key);
    }

    // ack public key
    create_header(&header, kOpAck, kPubKey, 0);
    status = send(sender_fd, header, HEADER_LENGTH, 0);
    free(header);
    if (status == -1) {
        error(sender_fd, "ack public key failed");
    } else {
        info(sender_fd, "ack public key success");
    }

    return status;
}

int send_data(int sender_fd, char *fname, char *pub_key, char sha256_str[65])
{
    FILE *src_file;
    src_file = fopen(fname, "rb");

    if (src_file == NULL) {
        error(sender_fd, "Error: can not open file %s", fname);
        return 1;
    } else {
        info(sender_fd, "Open file %s successfully", fname);
    }

    int status;

    size_t max_len = 1024;
    size_t seg_len;
    char *data_seg = malloc(max_len * sizeof(char));
    int last_seg = 0;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    packet_header_t header;
    packet_payload_t payload;
    // Read data & send
    while (1) {
        seg_len = fread(data_seg, sizeof(char), max_len, src_file);
        if (seg_len < max_len) {
            last_seg = 1;
        }

        SHA256_Update(&sha256, data_seg, seg_len);

        // Send data header
        create_header(&header, kOpData, kData, seg_len);
        status = send(sender_fd, header, HEADER_LENGTH, 0);
        free(header);
        if (status == -1) {
            error(sender_fd, "send data header failed");
            return status;
        } else {
            info(sender_fd, "send data header success");
        }

        //  Send data paylaod
        create_payload(&payload, 0, seg_len, data_seg);
        status = send(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(seg_len), 0);
        free(payload);
        if (status == -1) {
            error(sender_fd, "send data failed");
            return status;
        } else {
            info(sender_fd, "send data success");
        }
        //  Receive ack
        header = malloc(HEADER_LENGTH);
        status = recv(sender_fd, header, HEADER_LENGTH, 0);
        opcode_t opcode = get_opcode(header);
        free(header);
        if (status == -1 || opcode != kOpAck) {
            error(sender_fd, "recv ack failed");
            return status;
        } else {
            info(sender_fd, "recv ack success");
        }

        if (last_seg) break;
    }


    SHA256_Final(hash, &sha256);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(sha256_str + (i * 2), "%02x", hash[i]);
    }

    // End of data transfer
    fclose(src_file);

    // Send finish header
    create_header(&header, kOpFin, kNone, 0);
    status = send(sender_fd, header, HEADER_LENGTH, 0);
    free(header);
    if (status == -1) {
        error(sender_fd, "end sending failed");
        return status;
    } else {
        info(sender_fd, "end sending success");
    }
    // Receive finish ack
    header = malloc(HEADER_LENGTH);
    status = recv(sender_fd, header, HEADER_LENGTH, 0);
    opcode_t opcode = get_opcode(header);
    free(header);
    if (status == -1 || opcode != kOpAck) {
        error(sender_fd, "finish failed");
    } else {
        info(sender_fd, "finish success");
    }

    return status;
}
