#include <getopt.h>
#include <netinet/in.h>
#include <omp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "packet.h"
#include "pbar.h"
#include "rsa.h"
#include "sock.h"
#include "util.h"

size_t get_fsize(char *fname) {
  FILE *fp;
  size_t sz;
  fp = fopen(fname, "rb");
  if (fp != NULL) {
    fseek(fp, 0L, SEEK_END);
    sz = ftell(fp);
    fclose(fp);
  } else {
    sz = 0;
  }
  return sz;
}
int receiver_acked = 0;

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

  info(0, "Passcode = \033[30;47m %d \033[0m", *code);
  info(0, "Please send the passcode to receiver to obtain data");
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

int receive_pub_key(int sender_fd, char *fname, char **pub_key, size_t *pub_len,
                    size_t *fsize, size_t *ctext_fsize) {
  debug(sender_fd, "Receive pub key");
  int status;
  // recv public key header
  debug(sender_fd, "Receive data public key header");

  packet_header_t header = malloc(HEADER_LENGTH);
  status = recv(sender_fd, header, HEADER_LENGTH, 0);
  receiver_acked = 1;
  opcode_t opcode = get_opcode(header);
  payload_type_t payload_type = get_payload_type(header);
  *pub_len = get_payload_length(header);
  free(header);
  if (status == -1 || opcode != kOpPub || payload_type != kPubKey) {
    error(sender_fd, "Receive public key header failed");
    return -1;
  }

  // recv public key
  puts("");
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
  create_header(&header, kOpAck, kSize, sizeof(size_t));
  status = send(sender_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(sender_fd, "Ack public key failed");
    return -1;
  }

  packet_payload_t sz_payload;
  *fsize = get_fsize(fname);

  *ctext_fsize = (*fsize % MAX_PTEXT_CHUNK_LEN == 0) ? (*fsize / MAX_PTEXT_CHUNK_LEN) : (*fsize / MAX_PTEXT_CHUNK_LEN) + 1;
  *ctext_fsize *= CTEXT_CHUNK_LEN;

  int sz_payload_len = GET_PAYLOAD_PACKET_LEN(sizeof(size_t));
  create_payload(&sz_payload, 0, sizeof(size_t), (char *)ctext_fsize);
  status = send(sender_fd, sz_payload, sz_payload_len, 0);
  free(sz_payload);
  if (status == -1) {
    error(sender_fd, "Send file size failed");
    return -1;
  }

  return 0;
}

int encrypt_file(char *fname, FILE *ctext_file, char *pub_key, size_t pub_len,
                 char sha256_str[65], int num_thread) {
  FILE *src_file;
  src_file = fopen(fname, "rb");

  if (src_file == NULL) {
    error(0, "Fail opening source file: %s", fname);
    return -1;
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  size_t ptext_len;
  size_t max_ptext_len = MAX_PTEXT_CHUNK_LEN * num_thread;

  size_t last_ptext_chunk_len = 0;
  int num_ptext_chunk = num_thread;

  size_t max_ctext_len = CTEXT_CHUNK_LEN * num_thread;
  char ctext[max_ctext_len];

  int finish_encrypt = 0;

  omp_set_num_threads(num_thread);

  while (1) {
    size_t ctext_len = 0;
    char ptext[max_ptext_len];
    ptext_len = fread(ptext, sizeof(char), max_ptext_len, src_file);
    SHA256_Update(&sha256, (char *)ptext, ptext_len);

    if (ptext_len == 0) break;

    if (ptext_len < max_ptext_len) {
      finish_encrypt = 1;
      last_ptext_chunk_len = ptext_len % MAX_PTEXT_CHUNK_LEN;
      num_ptext_chunk = (ptext_len / MAX_PTEXT_CHUNK_LEN) + 1;
    }
    accumulated_sz += ptext_len;

#pragma omp parallel
    {
      int tid = omp_get_thread_num();
      if (tid < num_ptext_chunk) {
        size_t ctext_chunk_len = 0;
        unsigned char *ctext_chunk;
        if (finish_encrypt == 1 && tid == num_ptext_chunk - 1) {
          ctext_chunk =
              encrypt(pub_key, pub_len,
                      (const unsigned char *)(ptext + MAX_PTEXT_CHUNK_LEN * tid),
                      last_ptext_chunk_len, &ctext_chunk_len);
          memcpy(ctext + (CTEXT_CHUNK_LEN * tid), ctext_chunk, ctext_chunk_len);
        } else {
          ctext_chunk =
              encrypt(pub_key, pub_len,
                      (const unsigned char *)(ptext + MAX_PTEXT_CHUNK_LEN * tid),
                      MAX_PTEXT_CHUNK_LEN, &ctext_chunk_len);
        }
        memcpy(ctext + (CTEXT_CHUNK_LEN * tid), ctext_chunk, ctext_chunk_len);
#pragma omp critical
        ctext_len += ctext_chunk_len;
      }
    }
    fwrite(ctext, sizeof(char), ctext_len, ctext_file);

    if (finish_encrypt == 1) break;
  }

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
  char ctext[MAX_PAYLOAD_LEN];

  while (1) {
    size_t ctext_len = fread(ctext, 1, MAX_PAYLOAD_LEN, ctext_file);
    if (ctext_len < MAX_PAYLOAD_LEN) finish_send = 1;

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
    accumulated_sz += ctext_len;

    if (finish_send) break;
  }

  // End of data transfer
  debug(sender_fd, "Finish sending file");
  return 0;
}

int send_checksum(int sender_fd, char sha256_str[65]) {
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

static void *timer(void *argp) {
  long sender_fd = (long)argp;
  struct timespec tt1, tt2;
  clock_gettime(CLOCK_REALTIME, &tt1);
  while (!receiver_acked) {
    long pass_sec = tt2.tv_sec - tt1.tv_sec + 1;
    clock_gettime(CLOCK_REALTIME, &tt2);
    if (pass_sec > TIMEOUT_SEC) {
      puts("");
      fatal(sender_fd, "sender timout for waiting receiver");
    }
    printf("\rinfo:  session timout in %10ld seconds",
           (TIMEOUT_SEC - pass_sec));
    usleep(10000);
    fflush(stdout);
  }
  return 0;
}

static void help() {
  printf("%-12s %-20s %-30s\n", "-h", "--help", "show this message");
  printf("%-12s %-20s %-30s\n", "-i [ip]", "--server-ip [ip]",
         "specify server domain, default: localhost");
  printf("%-12s %-20s %-30s\n", "-p [port]", "--port [port]",
         "specify server port, default: 8700");
  printf("%-16s %-24s %-30s\n", "-t [num-thread]", "--num-thread [num-thread]",
         "number of thread for file decryption, default: 4");
  printf("%-12s %-20s %-30s\n", "-f [file]", "--file [file]",
         "file name to transfer, enter interactive mode if not specified");
}

int main(int argc, char *argv[]) {
  char *host = "localhost", *port = "8700", *fname = NULL, *num_thread = "4";
  const char optstr[] = "hi:p:t:f:";
  const static struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"server-ip", optional_argument, 0, 'i'},
      {"port", optional_argument, 0, 'p'},
      {"num-thread", optional_argument, 0, 't'},
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
      case 't':
        num_thread = argv[optind - 1];
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
    prompt(0, "Please specify number of threads, default = 4");
    printf("-> ");
    num_thread = malloc(sizeof(char) * 5);
    num_thread = fgets(num_thread, 5, stdin);
    num_thread[strlen(num_thread) - 1] = '\0';
    if (num_thread[0] == '\0') {
      sprintf(num_thread, "4");
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

  size_t fsize, ctext_fsize;
  char *data_pub_key;
  size_t data_pub_len;

  // timer for waiting receiver
  info(sender_fd, "Waiting for receiver...");
  pthread_t timer_thread;
  pthread_create(&timer_thread, NULL, timer, (void *)&sender_fd);
  status = receive_pub_key(sender_fd, fname, &data_pub_key, &data_pub_len,
                           &fsize, &ctext_fsize);
  if (status == -1) return -1;

  FILE *ctext_file = tmpfile();
  char sha256_str[65];
  info(0, "Start file encryption with %s threads", num_thread);
  pthread_t encrypt_pbar_thread;
  pthread_create(&encrypt_pbar_thread, NULL, progress_bar, (void *)fsize);
  status = encrypt_file(fname, ctext_file, data_pub_key, data_pub_len,
                        sha256_str, atoi(num_thread));
  while (!pbar_exit) asm("");
  info(0, "Finish file encryption");
  if (status == -1) return -1;

  rewind(ctext_file);
  info(sender_fd, "Start file transfer %s", fname);
  accumulated_sz = 0;
  pthread_t send_pbar_thread;
  pthread_create(&send_pbar_thread, NULL, progress_bar, (void *)ctext_fsize);
  status = send_data(sender_fd, ctext_file);
  while (!pbar_exit) asm("");
  fclose(ctext_file);
  info(sender_fd, "Finish file transfer %s", fname);

  info(sender_fd, "SHA256 checksum: %s", sha256_str);
  status = send_checksum(sender_fd, sha256_str);
  if (status == -1) return -1;

  if (interactive) {
    free0(host);
    free0(port);
    free0(fname);
  }
  return 0;
}
