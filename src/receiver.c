#include <assert.h>
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
#include <unistd.h>

#include "config.h"
#include "packet.h"
#include "pbar.h"
#include "rsa.h"
#include "sock.h"
#include "util.h"

int recv_intention(int receiver_fd, char *input_code) {
  debug(receiver_fd, "Receive intention");
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;
  // send code header
  debug(receiver_fd, "Send recv intention header");
  create_header(&header, kOpRequest, kCode, sizeof(const int));
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "Request failed");
    return -1;
  }

  // send code
  debug(receiver_fd, "Send code");
  int *code = malloc(sizeof(int));
  *code = atoi(input_code);
  create_payload(&payload, 0, GET_PAYLOAD_PACKET_LEN(sizeof(int)),
                 (char *)code);
  status = send(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(sizeof(int)), 0);
  copy_payload(payload, (char **)&code);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "Send code failed");
    return -1;
  }

  free(code);
  return 0;
}

int recv_fname(int receiver_fd, char **fname) {
  debug(receiver_fd, "Receive file name");
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;
  // receive ack
  debug(receiver_fd, "Receive ack");
  header = malloc(HEADER_LENGTH);
  status = recv(receiver_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  free(header);
  if (status == -1 || opcode != kOpAck) {
    error(receiver_fd, "Receive file name header & ack failed");
    return -1;
  }

  // receive file name
  debug(receiver_fd, "Receive file name");
  int max_len = GET_PAYLOAD_PACKET_LEN(MAX_PAYLOAD_LEN);
  payload = malloc(max_len);
  status = recv(receiver_fd, payload, max_len, 0);
  copy_payload(payload, fname);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "Receive file name failed");
    return -1;
  }

  return 0;
}

int send_pub_key(int receiver_fd, char *pub_key, size_t pub_len,
                 size_t *fsize) {
  debug(receiver_fd, "Send pub key");
  packet_header_t header;
  packet_payload_t payload;
  int status = 0;

  // send public key header
  debug(receiver_fd, "Send public key header");
  create_header(&header, kOpPub, kPubKey, pub_len);
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "Send public key header failed");
    return -1;
  }

  // send public key
  debug(receiver_fd, "Send public key");
  create_payload(&payload, 0, pub_len, pub_key);
  status = send(receiver_fd, payload, GET_PAYLOAD_PACKET_LEN(pub_len), 0);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "Send public key failed");
    return -1;
  }

  // receive ack
  debug(receiver_fd, "Receive ack");
  header = malloc(HEADER_LENGTH);
  status = recv(receiver_fd, header, HEADER_LENGTH, 0);
  opcode_t opcode = get_opcode(header);
  payload_type_t payload_type = get_payload_type(header);
  free(header);
  if (status == -1 || opcode != kOpAck || payload_type != kSize) {
    error(receiver_fd, "Receive ack failed");
    return -1;
  }

  int sz_payload_len = GET_PAYLOAD_PACKET_LEN(sizeof(size_t));
  packet_payload_t sz_payload = malloc(sz_payload_len);
  status = recv(receiver_fd, sz_payload, sz_payload_len, 0);
  size_t *file_sz;
  copy_payload(sz_payload, (char **)&file_sz);
  *fsize = *file_sz;
  free(sz_payload);
  free(file_sz);

  return 0;
}

int request_transfer(int receiver_fd, char *input_code, char **fname,
                     size_t *fsize, char *pub_key, size_t pub_len) {
  int status = 0;
  status = recv_intention(receiver_fd, input_code);
  if (status == -1) return -1;
  status = recv_fname(receiver_fd, fname);
  if (status == -1) return -1;
  status = send_pub_key(receiver_fd, pub_key, pub_len, fsize);
  if (status == -1) return -1;

  return 0;
}

int receive_data(int receiver_fd, FILE *dst_file, int *encrypt_on) {
  packet_header_t header;
  packet_payload_t payload;
  int status;

  // Receive data
  size_t payload_buf_len = GET_PAYLOAD_PACKET_LEN(MAX_PAYLOAD_LEN);

  int set_encrypt = 0;

  while (1) {
    // Receive header
    header = malloc(HEADER_LENGTH);
    status = retry_recv(receiver_fd, header, HEADER_LENGTH, 0);
    opcode_t opcode = get_opcode(header);
    payload_type_t payload_type = get_payload_type(header);
    size_t recv_data_len = get_payload_length(header);
    payload_buf_len = GET_PAYLOAD_PACKET_LEN(recv_data_len);
    free(header);

    if (status == -1) {
      error(receiver_fd, "Receive data header failed");
      return -1;
    } else if (opcode == kOpFin && payload_type == kHash) {
      break;
    } else if ((opcode != kOpCText && opcode != kOpPText) ||
               payload_type != kData) {
      error(receiver_fd, "Receive data header failed");
      return -1;
    }

    if (set_encrypt == 0) {
      set_encrypt = 1;
      if (opcode == kOpCText)
        *encrypt_on = 1;
      else
        *encrypt_on = 0;
    }

    // Receive data
    char *recv_data;
    payload = malloc(payload_buf_len);
    status = retry_recv(receiver_fd, payload, payload_buf_len, 0);
    copy_payload(payload, &recv_data);
    free(payload);
    if (status == -1) {
      error(receiver_fd, "Receive data failed");
      return -1;
    }
    accumulated_sz += recv_data_len;
    fwrite(recv_data, 1, recv_data_len, dst_file);
  }

  return 0;
}

int postprocess_file(FILE *tmp_file, char *fname, char *directory,
                     char *pri_key, size_t pri_len, char sha256_str[65],
                     int num_thread, size_t *ptext_fsize, int encrypt_on) {
  FILE *ptext_file;
  char *file_path = malloc(strlen(directory) + strlen(fname));
  sprintf(file_path, "%s/%s", directory, fname);
  ptext_file = fopen(file_path, "wb");
  if (ptext_file == NULL) {
    error(0, "Fail opening destination file");
    return -1;
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);

  if (encrypt_on) {
    *ptext_fsize = 0;
    int num_ctext_chunk = num_thread;
    int max_ctext_len = num_thread * CTEXT_CHUNK_LEN;
    char ctext[max_ctext_len];
    char ptext[num_thread * MAX_PTEXT_CHUNK_LEN];
    int finish_decrypt = 0;
    omp_set_num_threads(num_thread);

    while (1) {
      size_t ctext_len = fread(ctext, 1, max_ctext_len, tmp_file);
      size_t ptext_len = 0;

      if (ctext_len == 0) break;

      if (ctext_len < max_ctext_len) {
        num_ctext_chunk = ctext_len / CTEXT_CHUNK_LEN;
        finish_decrypt = 1;
      }

#pragma omp parallel
      {
        int tid = omp_get_thread_num();
        if (tid < num_ctext_chunk) {
          size_t ptext_chunk_len;
          unsigned char *ptext_chunk =
              decrypt(pri_key, pri_len,
                      (const unsigned char *)(ctext + CTEXT_CHUNK_LEN * tid),
                      CTEXT_CHUNK_LEN, &ptext_chunk_len);
          memcpy(ptext + (MAX_PTEXT_CHUNK_LEN * tid), ptext_chunk,
                 ptext_chunk_len);
#pragma omp critical
          ptext_len += ptext_chunk_len;
        }
      }
      accumulated_sz += ctext_len;
      *ptext_fsize += ptext_len;

      SHA256_Update(&sha256, (char *)ptext, ptext_len);
      fwrite(ptext, 1, ptext_len, ptext_file);

      if (finish_decrypt == 1) break;
    }
  } else {
    char recv_data[MAX_PAYLOAD_LEN];
    while (1) {
      size_t recv_data_len = fread(recv_data, 1, MAX_PAYLOAD_LEN, tmp_file);
      SHA256_Update(&sha256, (char *)recv_data, recv_data_len);
      fwrite(recv_data, 1, recv_data_len, ptext_file);
      accumulated_sz += recv_data_len;
      if (recv_data_len < MAX_PAYLOAD_LEN) break;
    }
  }

  SHA256_Final(hash, &sha256);

  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(sha256_str + (i * 2), "%02x", hash[i]);
  }

  return 0;
}

int compare_checksum(int receiver_fd, char sha256_str[65]) {
  packet_header_t header;
  packet_payload_t payload;
  int status;
  // recv SHA256
  debug(receiver_fd, "Receive SHA256 checksum");
  char *sha256_str_buf;
  size_t sha256_payload_len = GET_PAYLOAD_PACKET_LEN(65);
  payload = malloc(sha256_payload_len);
  status = recv(receiver_fd, payload, sha256_payload_len, 0);
  copy_payload(payload, &sha256_str_buf);
  free(payload);
  if (status == -1) {
    error(receiver_fd, "Receive sha256 failed");
    return -1;
  }

  // compare SHA256
  status = strncmp(sha256_str, sha256_str_buf, 65);
  if (status != 0) {
    error(receiver_fd, "Data distortion during file transfer");
    create_header(&header, kOpError, kNone, 0);
    status = send(receiver_fd, header, HEADER_LENGTH, 0);
    free(header);
    return -1;
  }

  // send ack SHA256
  debug(receiver_fd, "Send ack");
  create_header(&header, kOpAck, kNone, 0);
  status = send(receiver_fd, header, HEADER_LENGTH, 0);
  free(header);
  if (status == -1) {
    error(receiver_fd, "Finish failed");
    return -1;
  }
  return 0;
}

static void help() {
  printf("%-16s %-24s %-30s\n", "-h", "--help", "show this message");
  printf("%-16s %-24s %-30s\n", "-i [ip]", "--server-ip [ip]",
         "specify server domain, default: localhost");
  printf("%-16s %-24s %-30s\n", "-p [port]", "--port [port]",
         "specify server port, default: 8700");
  printf("%-16s %-24s %-30s\n", "-d [directory]", "--directory [directory]",
         "directory to store transferred file, default: .");
  printf("%-16s %-24s %-30s\n", "-c [code]", "--code [code]",
         "file transfer code, enter interactive mode if not specified");
  printf("%-16s %-24s %-30s\n", "-t [threads]", "--num-thread [threads]",
         "number of thread for file decryption, default: 4");
}

int main(int argc, char *argv[]) {
  char *host = "localhost", *port = "8700", *directory = ".",
       *input_code = NULL, *num_thread = "4";
  const char optstr[] = "hi:p:d:t:c:";
  const static struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"server-ip", optional_argument, 0, 'i'},
      {"port", optional_argument, 0, 'p'},
      {"directory", optional_argument, 0, 'd'},
      {"num-thread", optional_argument, 0, 't'},
      {"code", optional_argument, 0, 'c'}};
  int interactive = 1;
  while (1) {
    int c = getopt_long(argc, argv, optstr, long_options, NULL);
    if (c == -1) break;
    switch (c) {
      case 'h':
        printf("CASend Receiver\n");
        help();
        return 0;
      case 'i':
        host = argv[optind - 1];
        break;
      case 'p':
        port = argv[optind - 1];
        break;
      case 'd':
        directory = argv[optind - 1];
        break;
      case 't':
        num_thread = argv[optind - 1];
        break;
      case 'c':
        interactive = 0;
        input_code = argv[optind - 1];
        break;
      default:
        help();
        return -1;
    }
  }

  if (interactive) {
    printf("------------------------------------\n");
    printf("          CASend Receiver           \n");
    printf("------------------------------------\n");
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
    prompt(0, "Please specify directory to store file, default = .");
    printf("-> ");
    directory = malloc(sizeof(char) * 32);
    directory = fgets(directory, 32, stdin);
    directory[strlen(directory) - 1] = '\0';
    if (directory[0] == '\0') {
      sprintf(directory, ".");
    }
    prompt(0, "Please specify number of threads, default = 4");
    printf("-> ");
    num_thread = malloc(sizeof(char) * 5);
    num_thread = fgets(num_thread, 5, stdin);
    num_thread[strlen(num_thread) - 1] = '\0';
    if (num_thread[0] == '\0') {
      sprintf(num_thread, "4");
    }
    prompt(0, "Please specify file transfer code");
    printf("-> ");
    input_code = malloc(sizeof(char) * (CODE_LENGTH + 2));
    input_code = fgets(input_code, CODE_LENGTH + 2, stdin);
    input_code[strlen(input_code) - 1] = '\0';
    if (input_code[0] == '\0') {
      fatal(0, "input_code not specified");
    }
  }

  if (host == NULL || port == NULL) {
    error(0, "Server host or port not specified");
    exit(-1);
  } else {
    info(0, "Input host: %s, port: %s", host, port);
  }

  int receiver_fd __attribute__((unused)) = open_clientfd(host, port);
  if (receiver_fd == -1) {
    error(0, "Client file descriptor open failed");
    fatal(0, "Please check host and port again");
  } else {
    info(0, "Connection established, receiver_fd = %d", receiver_fd);
  }

  // Main process
  int status = 0;
  char *fname;
  size_t fsize;
  char *pub_key, *pri_key;
  size_t pub_len;
  size_t pri_len;
  status = generate_keys(&pub_key, &pri_key, &pri_len, &pub_len);
  if (status == -1) return status;

  info(receiver_fd, "Request file transfer: %s", input_code);

  status = request_transfer(receiver_fd, input_code, &fname, &fsize, pub_key,
                            pub_len);
  info(receiver_fd, "Encrypted file size = %d", fsize);

  if (status == -1) return status;
  char sha256_str[65];
  FILE *tmp_file = tmpfile();
  info(receiver_fd, "Start file transfer: %s/%s", directory, fname);

  int encrypt_on = 1;

  pthread_t recv_pbar_thread;
  pthread_create(&recv_pbar_thread, NULL, progress_bar, (void *)fsize);
  status = receive_data(receiver_fd, tmp_file, &encrypt_on);
  while (!pbar_exit) asm("");
  accumulated_sz = 0;
  pbar_exit = 0;
  info(receiver_fd, "Finish file transfer");

  rewind(tmp_file);
  info(0, "Start file postprocess");
  size_t ptext_fsize;
  pthread_t decrypt_pbar_thread;
  pthread_create(&decrypt_pbar_thread, NULL, progress_bar, (void *)fsize);
  status =
      postprocess_file(tmp_file, fname, directory, pri_key, pri_len, sha256_str,
                       atoi(num_thread), &ptext_fsize, encrypt_on);
  while (!pbar_exit) asm("");
  accumulated_sz = 0;
  pbar_exit = 0;
  fclose(tmp_file);
  info(0, "Finish file postprocess");
  info(0, "File size = %zu", ptext_fsize);
  if (status == -1) return status;

  info(receiver_fd, "SHA256 checksum: %s", sha256_str);
  status = compare_checksum(receiver_fd, sha256_str);
  if (status == -1) return status;
  info(receiver_fd, "Finish checksum checking");

  if (interactive) {
    free0(host);
    free0(port);
    free0(directory);
    free0(input_code);
  }
  return 0;
}
