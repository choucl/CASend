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

int send_intention(int sender_fd, char *pub_key, size_t pub_len) {
  info(sender_fd, "Send intention");
  packet_header_t header;
  packet_payload_t payload;
  int status;
  // send request header
  debug(sender_fd, "Send request header");
  create_header(&header, kOpCreate, kPubKey, pub_len);
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "Request failed");
    return -1;
  }

  // send code public key
  debug(sender_fd, "Send code pubkey");
  size_t key_payload_len = GET_PAYLOAD_PACKET_LEN(pub_len);
  create_payload(&payload, 0, key_payload_len, pub_key);
  status = send(sender_fd, payload, key_payload_len, 0);
  free(payload);
  if (status == -1) {
    error(sender_fd, "Send code public key failed");
    return -1;
  }

  return 0;
}

int recv_code(int sender_fd, int *code, char *pri_key, size_t pri_len) {
  info(sender_fd, "Receive code");
  packet_header_t header;
  packet_payload_t payload;
  int status;
  // receive ack & code header
  debug(sender_fd, "Receive ack");
  header = malloc(HEADER_LENGTH);
  status = recv(sender_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  payload_type_t payload_type = get_payload_type(header);
  size_t code_payload_len = get_payload_length(header);
  free(header);
  if (status == -1 || opcode != kOpAck || payload_type != kCode) {
    error(sender_fd, "Receive ack failed");
    return -1;
  }

  // receive code
  debug(sender_fd, "Receive code");
  char *code_ctext;
  size_t code_payload_length = GET_PAYLOAD_PACKET_LEN(code_payload_len);
  payload = malloc(code_payload_length);
  status = recv(sender_fd, payload, code_payload_length, 0);
  copy_payload(payload, &code_ctext);
  size_t code_ctext_len = get_cur_payload_size(payload);
  free(payload);
  if (status == -1) {
    error(sender_fd, "Receive code failed");
    return -1;
  }

  size_t code_ptext_len;
  unsigned char *code_ptext =
      decrypt(pri_key, pri_len, (const unsigned char *)code_ctext,
              code_ctext_len, &code_ptext_len);
  memcpy(code, code_ptext, code_ptext_len);

  info(sender_fd, "Get code %d", *code);

  return 0;
}

int send_fname(int sender_fd, char *fname) {
  info(sender_fd, "Send file name");
  packet_header_t header;
  packet_payload_t payload;
  int status;
  // send file name header
  debug(sender_fd, "Send file name header");
  size_t name_length = strlen(fname);
  create_header(&header, kOpData, kData, name_length);
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "Send file name header failed");
    return -1;
  }

  // send file name
  debug(sender_fd, "Send file name");
  create_payload(&payload, 0, name_length, fname);
  status = send(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(name_length), 0);
  free(payload);
  if (status == -1) {
    error(sender_fd, "Send file name failed");
    return -1;
  }

  return 0;
}

int register_new_transfer(int sender_fd, char *fname, char *pub_key,
                          size_t pub_len, char *pri_key, size_t pri_len) {
  int status = 0;
  status = send_intention(sender_fd, pub_key, pub_len);
  if (status == -1) return -1;
  int code;
  status = recv_code(sender_fd, &code, pri_key, pri_len);
  if (status == -1) return -1;
  status = send_fname(sender_fd, fname);
  if (status == -1) return -1;
  return 0;
}

int receive_pub_key(int sender_fd, char *fname, char **pub_key,
                    size_t *pub_len) {
  info(sender_fd, "Receive pub key");
  int status;
  // recv public key header
  debug(sender_fd, "Receive data public key header");
  packet_header_t header = malloc(HEADER_LENGTH);
  status = recv(sender_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  payload_type_t payload_type = get_payload_type(header);
  *pub_len = get_payload_length(header);
  free(header);
  if (status == -1 || opcode != kOpPub || payload_type != kPubKey) {
    error(sender_fd, "Receive public key header failed");
    return -1;
  }

  // recv public key
  debug(sender_fd, "Receive data public key");
  packet_payload_t payload = malloc(GET_PAYLOAD_PACKET_LEN(*pub_len));
  status = recv(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(*pub_len), 0);

  copy_payload(payload, pub_key);
  free(payload);
  if (status == -1) {
    error(sender_fd, "Receive public key failed");
    return -1;
  }

  // ack public key
  debug(sender_fd, "Ack data public key");
  create_header(&header, kOpAck, kPubKey, 0);
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "Ack public key failed");
    return -1;
  }

  return 0;
}

int send_data(int sender_fd, char *fname, char *pub_key, size_t pub_len,
              char sha256_str[65]) {
  FILE *src_file;
  src_file = fopen(fname, "rb");

  if (src_file == NULL) {
    error(sender_fd, "Fail opening source file: %s", fname);
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

  info(sender_fd, "Start file transfer");

  while (1) {
    ptext_len = fread(ptext, sizeof(char), max_ptext_len, src_file);
    SHA256_Update(&sha256, ptext, ptext_len);
    size_t last_chunk_len = 0;
    if (ptext_len < max_ptext_len) {
      last_chunk_len = ptext_len % ptext_chunk_len;
      finish_send = 1;
    }

    // Encrypt data
    size_t ctext_len = 0;
    char *ctext = malloc(MAX_PAYLOAD_LEN * sizeof(char));

    char ptext_chunk[ptext_chunk_len];
    int iter = (ptext_len / ptext_chunk_len) + finish_send;

    for (int i = 0; i < iter; i++) {
      size_t chunk_offset = ptext_chunk_len * i;

      if (finish_send == 1 && i == iter - 1) ptext_chunk_len = last_chunk_len;

      memcpy(ptext_chunk, ptext + chunk_offset, ptext_chunk_len);

      size_t ctext_chunk_len;
      unsigned char *ctext_chunk =
          encrypt(pub_key, pub_len, (const unsigned char *)ptext_chunk,
                  ptext_chunk_len, &ctext_chunk_len);
      memcpy(ctext + ctext_len, ctext_chunk, ctext_chunk_len);
      ctext_len += ctext_chunk_len;
    }

    // Send data header
    create_header(&header, kOpData, kData, ctext_len);
    status = retry_send(sender_fd, header, HEADER_LENGTH, 0);
    free(header);
    if (status == -1) {
      error(sender_fd, "Send data header failed");
      return -1;
    }

    //  Send data paylaod
    create_payload(&payload, 0, ctext_len, ctext);
    status =
        retry_send(sender_fd, payload, GET_PAYLOAD_PACKET_LEN(ctext_len), 0);
    free(payload);
    free(ctext);
    if (status == -1) {
      error(sender_fd, "Send data failed");
      return -1;
    }

    if (finish_send) break;
  }

  SHA256_Final(hash, &sha256);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(sha256_str + (i * 2), "%02x", hash[i]);
  }

  // End of data transfer
  info(sender_fd, "Finish sending file");
  fclose(src_file);

  // Send sha256 header
  debug(sender_fd, "Send SHA256 checksum header");
  create_header(&header, kOpFin, kHash, 65);
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "Send SHA256 header failed");
    return -1;
  }

  // Send sha256 payload
  debug(sender_fd, "Send SHA256 checksum");
  size_t sha256_payload_len = GET_PAYLOAD_PACKET_LEN(65);
  create_payload(&payload, 0, sha256_payload_len, sha256_str);
  status = send(sender_fd, payload, sha256_payload_len, 0);
  free(payload);
  if (status == -1) {
    error(sender_fd, "Send sha256 failed");
    return -1;
  }

  // Receive finish ack
  debug(sender_fd, "Receive finish ack");
  header = malloc(HEADER_LENGTH);
  status = recv(sender_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  free(header);
  if (status == -1 || opcode != kOpAck) {
    error(sender_fd, "Finish failed");
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  char *host = NULL, *port = NULL, *fname = NULL;

  if (argc != 7) {
    info(0, "Usage: ./client -i server_ip -p server_port -f file_name");
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
    error(0, "Server host or port not specified\n");
    exit(-1);
  } else {
    info(0, "Input host: %s, port: %s\n", host, port);
  }

  int sender_fd __attribute__((unused)) = open_clientfd(host, port);
  if (sender_fd == -1) {
    error(0, "Client file descriptor open failed\nPlease check host and port again");
    exit(-1);
  } else {
    info(0, "Connection established, sender_fd = %d\n", sender_fd);
  }

  // Main process
  int status = 0;

  char *code_pub_key, *code_pri_key;
  size_t code_pub_len, code_pri_len;

  generate_keys(&code_pub_key, &code_pri_key, &code_pri_len, &code_pub_len);

  info(sender_fd, "Register new file transfer\n");
  status = register_new_transfer(sender_fd, fname, code_pub_key, code_pub_len,
                                 code_pri_key, code_pri_len);
  if (status == -1) return -1;

  char *data_pub_key;
  size_t data_pub_len;
  info(sender_fd, "Waiting for receiver...\n");
  status = receive_pub_key(sender_fd, fname, &data_pub_key, &data_pub_len);
  if (status == -1) return -1;

  char sha256_str[65];

  info(sender_fd, "Start file transfer %s\n", fname);
  send_data(sender_fd, fname, data_pub_key, data_pub_len, sha256_str);
  debug(sender_fd, "SHA256 checksum: %s", sha256_str);

  if (status == -1) return -1;

  info(sender_fd, "Finish file transfer %s\n", fname);

  return 0;
}
