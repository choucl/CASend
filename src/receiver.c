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
#include "sock.h"
#include "util.h"

int recv_intention(int receiver_fd, char *input_code) {
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;
  // send code header
  create_header(&header, kOpRequest, kCode, sizeof(const int));
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "request failed");
    return -1;
  } else
    info(receiver_fd, "request success");

  // send code
  int *code = malloc(sizeof(int));
  *code = atoi(input_code);
  info(receiver_fd, "input code is %d", *code);
  create_payload(&payload, 0, GET_PAYLOAD_PACKET_LEN(sizeof(int)),
                 (char *)code);
  status = send(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(sizeof(int)), 0);
  copy_payload(payload, (char **)&code);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "send code failed");
    return -1;
  } else {
    info(receiver_fd, "send code success: %d", *code);
  }
  free(code);
  return 0;
}

int recv_fname(int receiver_fd, char **fname) {
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;
  // receive ack
  header = malloc(HEADER_LENGTH);
  status = recv(receiver_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  free(header);
  if (status == -1 || opcode != kOpAck) {
    error(receiver_fd, "recv file name header & ack failed");
    return -1;
  } else {
    info(receiver_fd, "recv file name header & ack success");
  }
  // Receive file name
  int max_len = GET_PAYLOAD_PACKET_LEN(MAX_PAYLOAD_LEN);
  payload = malloc(max_len);
  status = recv(receiver_fd, payload, max_len, 0);
  copy_payload(payload, fname);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "recv file name failed");
    return -1;
  } else {
    info(receiver_fd, "recv file name success: %s", *fname);
  }
  return 0;
}

int send_pub_key(int receiver_fd, char *data_pub_key) {
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;

  // send public key header
  create_header(&header, kOpPub, kPubKey, 64 * sizeof(char));
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "send public key header failed");
    return -1;
  } else {
    info(receiver_fd, "send public key header success");
  }
  // send public key
  create_payload(&payload, 0, 64, data_pub_key);
  status = send(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(64), 0);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "send public key failed");
    return -1;
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
    return -1;
  } else {
    info(receiver_fd, "recv ack success");
  }
  return 0;
}

int request_transfer(int receiver_fd, char *input_code, char **fname) {
  int status = 0;

  status = recv_intention(receiver_fd, input_code);
  if (status == -1) return -1;
  status = recv_fname(receiver_fd, fname);
  if (status == -1) return -1;
  char *pub_key = malloc(64 * sizeof(char));
  pub_key = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
  status = send_pub_key(receiver_fd, pub_key);
  if (status == -1) return -1;

  return 0;
}

int receive_data(int receiver_fd, char sha256_str[65], char *fname,
                 char *directory) {
  packet_header_t header;
  packet_payload_t payload;
  int status;

  FILE *dst_file;
  char *file_path = strcat(directory, fname);
  dst_file = fopen(file_path, "wb");
  if (dst_file == NULL) {
    error(receiver_fd, "Error opening destination file");
    return -1;
  } else {
    info(receiver_fd, "Open file %s successfully", file_path);
  }

  // Receive data
  size_t payload_buf_len = GET_PAYLOAD_PACKET_LEN(MAX_PAYLOAD_LEN);

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  while (1) {
    // Receive header
    header = malloc(HEADER_LENGTH);
    status = retry_recv(receiver_fd, header, HEADER_LENGTH, 0);
    opcode_t opcode = get_opcode(header);
    payload_type_t payload_type = get_payload_type(header);
    size_t seg_len = get_payload_length(header);
    payload_buf_len = GET_PAYLOAD_PACKET_LEN(seg_len);
    free(header);
    if (status == -1) {
      error(receiver_fd, "recv data header failed");
      return -1;
    } else if (opcode == kOpFin && payload_type == kHash) {
      info(receiver_fd, "recv finish");
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
    status = retry_recv(receiver_fd, payload, payload_buf_len, 0);
    copy_payload(payload, &data_seg);
    free(payload);
    if (status == -1) {
      error(receiver_fd, "recv data failed");
      return -1;
    } else {
      info(receiver_fd, "recv data success");
    }

    SHA256_Update(&sha256, data_seg, seg_len);

    fwrite(data_seg, sizeof(char), seg_len, dst_file);
    free(data_seg);
  }

  SHA256_Final(hash, &sha256);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(sha256_str + (i * 2), "%02x", hash[i]);
  }

  fclose(dst_file);

  // recv sha256
  char *sha256_str_buf;
  size_t sha256_payload_len = GET_PAYLOAD_PACKET_LEN(65);
  payload = malloc(sha256_payload_len);
  status = recv(receiver_fd, payload, sha256_payload_len, 0);
  copy_payload(payload, &sha256_str_buf);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "recv sha256 failed");
    return -1;
  } else {
    info(receiver_fd, "recv sha256 success");
  }

  // compare sha256
  status = strncmp(sha256_str, sha256_str_buf, 65);
  if (status != 0) {
    error(receiver_fd, "data between sender and receiver is inconsist");
    return -1;
  }

  // send ack sha256
  create_header(&header, kOpAck, kNone, 0);
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "finish failed");
    return -1;
  } else {
    info(receiver_fd, "finish success");
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

  status = request_transfer(receiver_fd, input_code, &fname);

  if (status == -1) return status;

  char sha256_str[65];
  status = receive_data(receiver_fd, sha256_str, fname, directory);

  info(receiver_fd, "sha256: %s", sha256_str);

  if (status == -1) return status;

  return 0;
}
