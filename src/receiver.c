#include <assert.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "packet.h"
#include "rsa.h"
#include "sock.h"
#include "util.h"

int recv_intention(int receiver_fd, char *input_code) {
  info(receiver_fd, "receive intention");
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;
  // send code header
  debug(receiver_fd, "send recv intention header");
  create_header(&header, kOpRequest, kCode, sizeof(const int));
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "request failed");
    return -1;
  }

  // send code
  debug(receiver_fd, "send code");
  int *code = malloc(sizeof(int));
  *code = atoi(input_code);
  create_payload(&payload, 0, GET_PAYLOAD_PACKET_LEN(sizeof(int)),
                 (char *)code);
  status = send(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(sizeof(int)), 0);
  copy_payload(payload, (char **)&code);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "send code failed");
    return -1;
  }

  free(code);
  return 0;
}

int recv_fname(int receiver_fd, char **fname) {
  info(receiver_fd, "receive file name");
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;
  // receive ack
  debug(receiver_fd, "recv ack");
  header = malloc(HEADER_LENGTH);
  status = recv(receiver_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  free(header);
  if (status == -1 || opcode != kOpAck) {
    error(receiver_fd, "recv file name header & ack failed");
    return -1;
  }

  // receive file name
  debug(receiver_fd, "recv file name");
  int max_len = GET_PAYLOAD_PACKET_LEN(MAX_PAYLOAD_LEN);
  payload = malloc(max_len);
  status = recv(receiver_fd, payload, max_len, 0);
  copy_payload(payload, fname);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "recv file name failed");
    return -1;
  }

  return 0;
}

int send_pub_key(int receiver_fd, char *pub_key) {
  info(receiver_fd, "send pub key");
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;

  // send public key header
  debug(receiver_fd, "send public key header");
  size_t key_len = strlen(pub_key);
  create_header(&header, kOpPub, kPubKey, key_len * sizeof(char));
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "send public key header failed");
    return -1;
  }

  // send public key
  debug(receiver_fd, "send public key");
  create_payload(&payload, 0, key_len, pub_key);
  status = send(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(key_len), 0);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "send public key failed");
    return -1;
  }

  // receive ack
  debug(receiver_fd, "recv ack");
  header = malloc(HEADER_LENGTH);
  status = recv(receiver_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  free(header);
  if (status == -1 || opcode != kOpAck) {
    error(receiver_fd, "recv ack failed");
    return -1;
  }

  return 0;
}

int request_transfer(int receiver_fd, char *input_code, char **fname,
                     char *pub_key) {
  int status = 0;
  status = recv_intention(receiver_fd, input_code);
  if (status == -1) return -1;
  status = recv_fname(receiver_fd, fname);
  if (status == -1) return -1;
  status = send_pub_key(receiver_fd, pub_key);
  if (status == -1) return -1;

  return 0;
}

int receive_data(int receiver_fd, char sha256_str[65], char *fname,
                 char *directory, char *pri_key, size_t pri_len, char *pub_key,
                 size_t pub_len) {
  packet_header_t header;
  packet_payload_t payload;
  int status;

  FILE *dst_file;
  char *file_path = malloc(strlen(directory) + strlen(fname));
  sprintf(file_path, "%s%s", directory, fname);
  dst_file = fopen(file_path, "wb");
  if (dst_file == NULL) {
    error(receiver_fd, "Error opening destination file");
    return -1;
  }

  // Receive data
  size_t payload_buf_len = GET_PAYLOAD_PACKET_LEN(MAX_PAYLOAD_LEN);

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  info(receiver_fd, "start file trasfer");
  while (1) {
    // Receive header
    header = malloc(HEADER_LENGTH);
    status = retry_recv(receiver_fd, header, HEADER_LENGTH, 0);
    opcode_t opcode = get_opcode(header);
    payload_type_t payload_type = get_payload_type(header);
    size_t ctext_len = get_payload_length(header);
    payload_buf_len = GET_PAYLOAD_PACKET_LEN(ctext_len);
    free(header);

    if (status == -1) {
      error(receiver_fd, "recv data header failed");
      return -1;
    } else if (opcode == kOpFin && payload_type == kHash) {
      break;
    } else if (opcode != kOpData || payload_type != kData) {
      error(receiver_fd, "recv data header failed");
      return -1;
    }

    // Receive data
    char *ctext;
    payload = malloc(payload_buf_len);
    status = retry_recv(receiver_fd, payload, payload_buf_len, 0);
    copy_payload(payload, &ctext);
    free(payload);
    if (status == -1) {
      error(receiver_fd, "recv data failed");
      return -1;
    }

    char ptext[MAX_PAYLOAD_LEN / 2];
    size_t ptext_len = 0;
    size_t ctext_chunk_len = 256;
    char ctext_chunk[ctext_chunk_len];

    int iter = ctext_len / ctext_chunk_len;

    for (int i = 0; i < iter; i++) {
      memcpy(ctext_chunk, ctext + ctext_chunk_len * i, ctext_chunk_len);
      size_t ptext_chunk_len;
      unsigned char *ptext_chunk =
          decrypt(pri_key, pri_len, (const unsigned char *)ctext_chunk,
                  ctext_chunk_len, &ptext_chunk_len);
      memcpy(ptext + ptext_len, ptext_chunk, ptext_chunk_len);
      ptext_len += ptext_chunk_len;
    }

    SHA256_Update(&sha256, (char *)ptext, ptext_len);

    fwrite(ptext, sizeof(char), ptext_len, dst_file);
  }

  info(receiver_fd, "finish file transfer");

  SHA256_Final(hash, &sha256);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(sha256_str + (i * 2), "%02x", hash[i]);
  }

  fclose(dst_file);

  // recv sha256
  debug(receiver_fd, "recv sha256 checksum");
  char *sha256_str_buf;
  size_t sha256_payload_len = GET_PAYLOAD_PACKET_LEN(65);
  payload = malloc(sha256_payload_len);
  status = recv(receiver_fd, payload, sha256_payload_len, 0);
  copy_payload(payload, &sha256_str_buf);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "recv sha256 failed");
    return -1;
  }

  // compare sha256
  status = strncmp(sha256_str, sha256_str_buf, 65);
  if (status != 0) {
    error(receiver_fd, "data between sender and receiver is inconsist");
    create_header(&header, kOpError, kNone, 0);
    status = send(receiver_fd, header, HEADER_LENGTH, 0);
    free(header);
    return -1;
  }

  // send ack sha256
  debug(receiver_fd, "send ack");
  create_header(&header, kOpAck, kNone, 0);
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "finish failed");
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  char *host = NULL, *port = NULL, *directory = NULL, *input_code = NULL;

  if (argc != 9) {
    printf(
        "Usage: ./client -i server_ip -p server_port -d directory -c code\n");
    return -1;
  }

  --argc;
  ++argv;
  if (argc > 0 && **argv == '-' && (*argv)[1] == 'i') {
    --argc;
    ++argv;
    if (argc < 1) return -1;
    host = malloc(sizeof(char) * strlen(*argv) + 1);
    strncpy(host, *argv, strlen(*argv));
  }

  --argc;
  ++argv;
  if (argc > 0 && **argv == '-' && (*argv)[1] == 'p') {
    --argc;
    ++argv;
    if (argc < 1) return -1;
    port = malloc(sizeof(char) * strlen(*argv) + 1);
    strncpy(port, *argv, strlen(*argv));
  }

  --argc;
  ++argv;
  if (argc > 0 && **argv == '-' && (*argv)[1] == 'd') {
    --argc;
    ++argv;
    if (argc < 1) return -1;
    directory = malloc(sizeof(char) * strlen(*argv) + 1);
    sprintf(directory, "%s/", *argv);
  }

  --argc;
  ++argv;
  if (argc > 0 && **argv == '-' && (*argv)[1] == 'c') {
    --argc;
    ++argv;
    if (argc < 1) return -1;
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
  char *fname;
  char *pub_key, *pri_key;
  size_t pub_len;
  size_t pri_len;
  generate_keys(&pub_key, &pri_key, &pri_len, &pub_len);

  printf("[Info] Request file transfer: %s\n", input_code);
  status = request_transfer(receiver_fd, input_code, &fname, pub_key);

  if (status == -1) return status;

  char sha256_str[65];
  printf("[Info] Start file transfer: %s%s\n", directory, fname);
  status = receive_data(receiver_fd, sha256_str, fname, directory, pri_key,
                        pri_len, pub_key, pub_len);

  debug(receiver_fd, "sha256: %s", sha256_str);

  if (status == -1) return status;
  printf("[Info] Finish file transfer: %s%s\n", directory, fname);

  return 0;
}
