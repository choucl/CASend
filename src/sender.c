#include <getopt.h>
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
  debug(sender_fd, "Send intention");
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
  debug(sender_fd, "Receive code");
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
  debug(sender_fd, "Send file name");
  packet_header_t header;
  packet_payload_t payload;
  int status;
  // send file name header
  debug(sender_fd, "Send file name header");
  size_t name_length = strlen(fname) + 1;
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
  debug(sender_fd, "Receive pub key");
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

int encrypt_file(char *fname, FILE *ctext_file, char *pub_key, size_t pub_len,
                 char sha256_str[65]) {
  FILE *src_file;
  src_file = fopen(fname, "rb");

  if (src_file == NULL) {
    error(0, "Fail opening source file: %s", fname);
    return -1;
  }

  size_t ptext_len;
  size_t max_ptext_len = 128;

  int finish_encrypt = 0;

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  // Read data & send
  char ptext[max_ptext_len];

  debug(0, "Start file encryption");

  while (1) {
    ptext_len = fread(ptext, sizeof(char), max_ptext_len, src_file);
    SHA256_Update(&sha256, ptext, ptext_len);
    if (ptext_len < max_ptext_len) {
      finish_encrypt = 1;
    }

    // Encrypt data
    size_t ctext_len = 0;
    unsigned char *ctext= encrypt(pub_key, pub_len,
                                 (const unsigned char *)ptext,
                                  ptext_len, &ctext_len);
    // Write to tmp file
    fwrite(ctext, 1, ctext_len, ctext_file);
    if (finish_encrypt == 1)
      break;
  }

  info(0, "Finish file encryption");
  SHA256_Final(hash, &sha256);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(sha256_str + (i * 2), "%02x", hash[i]);
  }

  fclose(src_file);

  return 0;
}


int send_data(int sender_fd, FILE *ctext_file) {
  int status;
  packet_header_t header;
  packet_payload_t payload;
  int finish_send = 0;
  // Read data & send
  //char ptext[max_ptext_len];
  char ctext[MAX_PAYLOAD_LEN];

  info(sender_fd, "Start file transfer");

  while (1) {
    size_t ctext_len = fread(ctext, 1, MAX_PAYLOAD_LEN, ctext_file);
    if (ctext_len < MAX_PAYLOAD_LEN)
      finish_send = 1;

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
    if (status == -1) {
      error(sender_fd, "Send data failed");
      return -1;
    }

    if (finish_send) break;
  }

  // End of data transfer
  debug(sender_fd, "Finish sending file");
  return 0;
}

int compare_check_sum(int sender_fd, char sha256_str[65]) {
  int status;
  packet_header_t header;
  packet_payload_t payload;
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

static void help() {
  printf("%-12s %-20s %-30s\n", "-h", "--help", "show this message");
  printf("%-12s %-20s %-30s\n", "-i [ip]", "--server-ip [ip]",
         "specify server domain, default: localhost");
  printf("%-12s %-20s %-30s\n", "-p [port]", "--port [port]",
         "specify server port, default: 8700");
  printf("%-12s %-20s %-30s\n", "-f [file]", "--file [file]",
         "file name to transfer, enter interactive mode if not specified");
}

int main(int argc, char *argv[]) {
  char *host = "localhost", *port = "8700", *fname = NULL;
  const char optstr[] = "hi:p:f:";
  const static struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"server-ip", optional_argument, 0, 'i'},
      {"port", optional_argument, 0, 'p'},
      {"file", optional_argument, 0, 'f'}};
  int interactive = 1;
  while (1) {
    int c = getopt_long(argc, argv, optstr, long_options, NULL);
    if (c == -1) break;
    switch (c) {
      case 'h':
        printf("CASend Sender\n");
        help();
        return 0;
      case 'i':
        host = argv[optind - 1];
        break;
      case 'p':
        port = argv[optind - 1];
        break;
      case 'f':
        interactive = 0;
        fname = argv[optind - 1];
        break;
      default:
        help();
        return -1;
    }
  }

  if (interactive) {
    printf("----------------------------------\n");
    printf("          CASend Sender           \n");
    printf("----------------------------------\n");
    prompt(0, "Please specify server ip, default = localhost");
    printf("-> ");
    host = malloc(sizeof(char) * 32);
    host = fgets(host, 32, stdin);
    host[strlen(host) - 1] = '\0';
    if (host[0] == '\0') {
      sprintf(host, "localhost");
    }
    prompt(0, "Please specify server port, default = 8700");
    printf("-> ");
    port = malloc(sizeof(char) * 6);
    port = fgets(port, 6, stdin);
    port[strlen(port) - 1] = '\0';
    if (port[0] == '\0') {
      sprintf(port, "8700");
    }
    prompt(0, "Please specify file name to transfer");
    printf("-> ");
    fname = malloc(sizeof(char) * 32);
    fname = fgets(fname, 32, stdin);
    fname[strlen(fname) - 1] = '\0';
    if (fname[0] == '\0') {
      fatal(0, "fname not specified");
    }
  }

  if (host == NULL || port == NULL) {
    fatal(0, "Server host or port not specified");
  } else {
    info(0, "Input host: %s, port: %s", host, port);
  }

  int sender_fd __attribute__((unused)) = open_clientfd(host, port);
  if (sender_fd == -1) {
    error(0, "Client file descriptor open failed");
    fatal(0, "Please check host and port again");
  } else {
    info(0, "Connection established, sender_fd = %d", sender_fd);
  }

  // Main process
  int status = 0;

  char *code_pub_key, *code_pri_key;
  size_t code_pub_len, code_pri_len;

  generate_keys(&code_pub_key, &code_pri_key, &code_pri_len, &code_pub_len);

  info(sender_fd, "Register new file transfer");
  status = register_new_transfer(sender_fd, fname, code_pub_key, code_pub_len,
                                 code_pri_key, code_pri_len);
  if (status == -1) return -1;

  char *data_pub_key;
  size_t data_pub_len;
  info(sender_fd, "Waiting for receiver...");
  status = receive_pub_key(sender_fd, fname, &data_pub_key, &data_pub_len);
  if (status == -1) return -1;

  FILE *ctext_file = tmpfile();
  char sha256_str[65];
  status = encrypt_file(fname, ctext_file, data_pub_key, data_pub_len, sha256_str);
  if (status == -1) return -1;
  rewind(ctext_file);

  info(sender_fd, "Start file transfer %s\n", fname);
  status = send_data(sender_fd, ctext_file);
  fclose(ctext_file);
  if (status == -1) return -1;
  status = compare_check_sum(sender_fd, sha256_str);
  if (status == -1) return -1;
  info(sender_fd, "SHA256 checksum: %s", sha256_str);

  if (status == -1) return -1;

  info(sender_fd, "Finish file transfer %s", fname);

  if (interactive) {
    free0(host);
    free0(port);
    free0(fname);
  }
  return 0;
}
