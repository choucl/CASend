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
#include "rsa.h"

void print_raw(unsigned char *str, size_t len) {
  for (int i = 0; i < len; i++) {
    printf("%02x", *(str + i));
    if ((i + 1) % 16 == 0)
      printf("\n");
  }
  printf("\n");
}

int send_intention(int sender_fd, char fname_pub_key[64]) {
  packet_header_t header;
  packet_payload_t payload;
  int status;
  // send request header
  create_header(&header, kOpCreate, kPubKey, 64 * sizeof(char));
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "request failed");
    return -1;
  }

  // send file name public key
  size_t key_payload_len = GET_PAYLOAD_PACKET_LEN(64);
  create_payload(&payload, 0, key_payload_len, fname_pub_key);
  status = send(sender_fd, payload, key_payload_len, 0);
  free(payload);
  if (status == -1) {
    error(sender_fd, "send file name public key failed");
    return -1;
  }

  return 0;
}

int recv_code(int sender_fd, int *code) {
  packet_header_t header;
  packet_payload_t payload;
  int status;
  // receive ack & code header
  header = malloc(HEADER_LENGTH);
  status = recv(sender_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  payload_type_t payload_type = get_payload_type(header);
  free(header);
  if (status == -1 || opcode != kOpAck || payload_type != kCode) {
    error(sender_fd, "recv ack failed");
    return -1;
  }

  // receive code
  size_t code_payload_length = GET_PAYLOAD_PACKET_LEN(sizeof(const int));
  payload = malloc(code_payload_length);
  status = recv(sender_fd, payload, code_payload_length, 0);
  copy_payload(payload, (char **)&code);
  free(payload);
  if (status == -1) {
    error(sender_fd, "recv code failed");
    return -1;
  }

  printf("[Info] Got code %d\n", *code);
  free(code);

  return 0;
}

int send_fname(int sender_fd, char *fname) {
  packet_header_t header;
  packet_payload_t payload;
  int status;
  // send file name header
  size_t name_length = strlen(fname);
  create_header(&header, kOpData, kData, name_length);
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "send file name header failed");
    return -1;
  }

  // send file name
  create_payload(&payload, 0, name_length, fname);
  status = send(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(name_length), 0);
  free(payload);
  if (status == -1) {
    error(sender_fd, "send file name failed");
    return -1;
  }

  return 0;
}

int register_new_transfer(int sender_fd, char *fname) {
  int status = 0;
  char *fname_pub_key =
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  status = send_intention(sender_fd, fname_pub_key);
  if (status == -1) return -1;
  int code;
  status = recv_code(sender_fd, &code);
  if (status == -1) return -1;
  status = send_fname(sender_fd, fname);
  if (status == -1) return -1;
  return 0;
}

int receive_pub_key(int sender_fd, char *fname, char **pub_key) {
  int status;
  // recv public key header
  packet_header_t header = malloc(HEADER_LENGTH);
  status = recv(sender_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  payload_type_t payload_type = get_payload_type(header);
  size_t key_ken = get_payload_length(header);
  free(header);
  if (status == -1 || opcode != kOpPub || payload_type != kPubKey) {
    error(sender_fd, "recv public key header failed");
    return -1;
  }

  // recv public key
  packet_payload_t payload = malloc(GET_PAYLOAD_PACKET_LEN(key_ken));
  status = recv(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(key_ken), 0);

  copy_payload(payload, pub_key);
  free(payload);
  if (status == -1) {
    error(sender_fd, "recv public key failed");
    return -1;
  }

  // ack public key
  create_header(&header, kOpAck, kPubKey, 0);
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "ack public key failed");
    return -1;
  }

  return 0;
}

int send_data(int sender_fd, char *fname, char *pub_key, char sha256_str[65]) {
  FILE *src_file;
  src_file = fopen(fname, "rb");

  if (src_file == NULL) {
    error(sender_fd, "Error: can not open file %s", fname);
    return 1;
  }

  int status;


  size_t ptext_len;
  size_t ptext_chunk_len = 128;
  size_t max_ptext_len = (MAX_PAYLOAD_LEN / 256) * ptext_chunk_len;

  int finish_send = 0;

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  packet_header_t header;
  packet_payload_t payload;
  // Read data & send
  char ptext[max_ptext_len];

  int send_time = 0;

  while (1) {

    //char *ptext = malloc(max_ptext_len * sizeof(char));
    ptext_len = fread(ptext, sizeof(char), max_ptext_len, src_file);
    //info(sender_fd, "ptext(%zu): %s", ptext_len, ptext);
    //printf("send time %d, ptext len %zu\n", send_time++, ptext_len);
    SHA256_Update(&sha256, ptext, ptext_len);
    size_t last_chunk_len = 0;
    if (ptext_len < max_ptext_len) {
      last_chunk_len = ptext_len % ptext_chunk_len;
      info(sender_fd, "last_chunk_len %zu bytes", last_chunk_len);
      //memset(ptext + ptext_len, 0, pad_len); // padding
      //ptext_len += pad_len;
      finish_send = 1;
    }

    // Encrypt data
    size_t ctext_len = 0;
    char *ctext = malloc(MAX_PAYLOAD_LEN * sizeof(char));

    char ptext_chunk[ptext_chunk_len];
    size_t pub_len = 451;
    int iter = (ptext_len / ptext_chunk_len) + finish_send;

    for (int i = 0; i < iter; i++) {
      size_t chunk_offset = ptext_chunk_len * i;

      if (finish_send == 1 && i == iter - 1)
        ptext_chunk_len = last_chunk_len;

      memcpy(ptext_chunk, ptext + chunk_offset, ptext_chunk_len);

      size_t ctext_chunk_len;
      unsigned char *ctext_chunk = encrypt(pub_key, pub_len, (const unsigned char*)ptext_chunk, &ctext_chunk_len, ptext_chunk_len);
      memcpy(ctext + ctext_len, ctext_chunk, ctext_chunk_len);
      if (ctext_chunk_len != 256) {
        info(sender_fd, "ctext chunk len != 256");
      }
      ctext_len += ctext_chunk_len;
    }


    // Send data header
    create_header(&header, kOpData, kData, seg_len);
    status = retry_send(sender_fd, header, HEADER_LENGTH, 0);
    free(header);
    if (status == -1) {
      error(sender_fd, "send data header failed");
      return -1;
    }

    //  Send data paylaod
    create_payload(&payload, 0, seg_len, data_seg);
    status = retry_send(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(seg_len), 0);
    free(payload);
    free(ctext);
    if (status == -1) {
      error(sender_fd, "send data failed");
      return -1;
    }

    if (finish_send) break;
  }

  SHA256_Final(hash, &sha256);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(sha256_str + (i * 2), "%02x", hash[i]);
  }

  // End of data transfer
  fclose(src_file);

  // Send sha256 header
  create_header(&header, kOpFin, kHash, 65);
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "send sha256 header failed");
    return -1;
  }

  // Send sha256 payload
  size_t sha256_payload_len = GET_PAYLOAD_PACKET_LEN(65);
  create_payload(&payload, 0, sha256_payload_len, sha256_str);
  status = send(sender_fd, payload, sha256_payload_len, 0);
  free(payload);
  if (status == -1) {
    error(sender_fd, "send sha256 failed");
    return -1;
  }

  // Receive finish ack
  header = malloc(HEADER_LENGTH);
  status = recv(sender_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  free(header);
  if (status == -1 || opcode != kOpAck) {
    error(sender_fd, "finish failed");
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  char *host = NULL, *port = NULL, *fname = NULL;

  if (argc != 7) {
    printf("Usage: ./client -i server_ip -p server_port -f file_name\n");
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
  if (argc > 0 && **argv == '-' && (*argv)[1] == 'f') {
    --argc;
    ++argv;
    if (argc < 1) return -1;
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

  printf("[Info] Register new file transfer\n");
  status = register_new_transfer(sender_fd, fname);
  if (status == -1)
    return -1;

  char *pub_key;
  printf("[Info] Waiting for receiver...\n");
  status = receive_pub_key(sender_fd, fname, &pub_key);

  if (status == -1)
    return -1;

  printf("Get public key: %s", pub_key);

  char sha256_str[65];

  printf("[Info] Start file transfer %s\n", fname);
  send_data(sender_fd, fname, pub_key, sha256_str);
  info(sender_fd, "sha256: %s", sha256_str);

  if (status == -1)
    return -1;

  printf("[Info] Finish file transfer %s\n", fname);

  return 0;
}
