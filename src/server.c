#include <getopt.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "packet.h"
#include "rsa.h"
#include "sock.h"
#include "util.h"

static pthread_mutex_t mutex;

typedef struct service_entry service_entry_t;

struct service_entry {
  int code;  // generated code
  int name_length;
  long sender_fd;
  long receiver_fd;
  char *name;
  packet_header_t header_buffer;
  packet_payload_t payload_buffer;
};

int occupy_count = 0;
service_entry_t *service_table[TABLE_SIZE];

static int gen_code(int code_length) {
  srand(time(NULL));
  int code = 0;
  do {
    code = rand() % (int)pow(10, code_length);
  } while (code < (int)pow(10, code_length - 1));
  return code;
}

static service_entry_t *create_table_entry(int clientfd, int code_length) {
  int code;
  int position;
  do {
    code = gen_code(CODE_LENGTH);
    position = code % TABLE_SIZE;
  } while (service_table[position] != NULL);

  service_entry_t *new_entry = malloc(sizeof(service_entry_t));
  new_entry->code = code;
  new_entry->sender_fd = clientfd;
  new_entry->receiver_fd = -1;
  new_entry->name = NULL;
  new_entry->name_length = -1;
  new_entry->header_buffer = malloc(HEADER_LENGTH);
  new_entry->payload_buffer = malloc(GET_PAYLOAD_PACKET_LEN(MAX_PAYLOAD_LEN));

  service_table[position] = new_entry;
  occupy_count++;
  return new_entry;
}

static int send_intention_handler(service_entry_t **entry, long clientfd,
                                  int key_length) {
  int status = 0;
  info(clientfd, "received send intention");
  // receive pubkey payload
  int key_payload_length = GET_PAYLOAD_PACKET_LEN(key_length);
  packet_payload_t recv_pubkey_payload = malloc(key_payload_length);
  status = recv(clientfd, recv_pubkey_payload, key_payload_length, 0);
  if (status == -1) {
    error(clientfd, "recv sender public key payload failed.");
    free0(recv_pubkey_payload);
    return -1;
  }
  char *sender_pubkey = NULL;
  status = copy_payload(recv_pubkey_payload, &sender_pubkey);
  free0(recv_pubkey_payload);
  if (status <= 0) {
    error(clientfd, "parsing sender public key failed");
    free0(sender_pubkey);
    return -1;
  }
  debug(clientfd, "received sender public key");

  if (occupy_count == TABLE_SIZE) {
    warning(clientfd, "no vacancy, try again later");
    packet_header_t send_err_header;
    create_header(&send_err_header, kOpError, kNone, 0);
    send(clientfd, send_err_header, HEADER_LENGTH, 0);
    free0(send_err_header);
    return -1;
  }

  // create entry
  pthread_mutex_lock(&mutex);
  *entry = create_table_entry(clientfd, CODE_LENGTH);
  pthread_mutex_unlock(&mutex);
  debug(clientfd, "entry creation complete, code = %d", (*entry)->code);

  size_t cipher_code_len;
  unsigned char *cipher_code = NULL;
  if (key_length > 0) {
    // encryption
    cipher_code =
        encrypt(sender_pubkey, key_length, (unsigned char *)&(*entry)->code,
                sizeof(int), &cipher_code_len);
  } else {
    cipher_code = (unsigned char *)&(*entry)->code;
    cipher_code_len = sizeof(int);
  }
  free0(sender_pubkey);

  // send code header
  debug(clientfd, "sending ack header");
  packet_header_t send_ack_header;
  create_header(&send_ack_header, kOpAck, kCode, cipher_code_len);
  status = send(clientfd, send_ack_header, HEADER_LENGTH, 0);
  free0(send_ack_header);
  if (status <= 0) {
    error(clientfd, "fail sending ack header");
    return -1;
  }

  // send code payload
  debug(clientfd, "sending code payload");
  packet_payload_t send_code_payload;
  int payload_size = create_payload(&send_code_payload, 0, cipher_code_len,
                                    (char *)cipher_code);
  if ((status = payload_size) <= 0) {
    error(clientfd, "fail creating code payload");
    free0(send_code_payload);
    return -1;
  }
  status = send(clientfd, send_code_payload, payload_size, 0);
  if (status <= 0) {
    error(clientfd, "fail sending code payload");
    free0(send_code_payload);
    return -1;
  }
  free0(send_code_payload);
  if (cipher_code) free0(cipher_code);

  // receive name header
  packet_header_t recv_name_header = malloc(HEADER_LENGTH);
  status = recv(clientfd, recv_name_header, HEADER_LENGTH, 0);
  if (status <= 0 || ((check_header_op(recv_name_header, kOpPText) <= 0) &&
                      (check_header_op(recv_name_header, kOpCText) <= 0))) {
    error(clientfd, "recv name header failed");
    return -1;
  }
  int name_length = get_payload_length(recv_name_header);
  free0(recv_name_header);

  // receive name payload
  int name_payload_length = GET_PAYLOAD_PACKET_LEN(name_length);
  packet_payload_t recv_name_payload = malloc(name_payload_length);
  status = recv(clientfd, recv_name_payload, name_payload_length, 0);
  if (status == -1) {
    error(clientfd, "recv name payload failed");
    free0(recv_name_payload);
    return -1;
  }
  char *name = NULL;
  if (copy_payload(recv_name_payload, &name) == -1 || name[0] == 0) {
    error(clientfd, "parsing name failed");
    free0(recv_name_payload);
    free0(name);
    return -1;
  }
  free0(recv_name_payload);
  debug(clientfd, "name payload received - %s", name);
  (*entry)->name = name;
  (*entry)->name_length = name_length;
  return status;
}

static int receiver_request_handler(service_entry_t **entry, long clientfd) {
  info(clientfd, "receive request intention");
  int status = 0;

  // receive code
  int code_payload_length = GET_PAYLOAD_PACKET_LEN(sizeof(int));
  packet_payload_t recv_code_payload = malloc(code_payload_length);
  status = recv(clientfd, recv_code_payload, code_payload_length, 0);
  if (status <= 0) {
    error(clientfd, "fail receiving code payload");
    free0(recv_code_payload);
    return -1;
  }
  int *recv_code;
  status = copy_payload(recv_code_payload, (char **)&recv_code);
  if (status <= 0) {
    error(clientfd, "fail copying code payload");
    free0(recv_code_payload);
    free0(recv_code);
    return -1;
  }
  free0(recv_code_payload);
  debug(clientfd, "recv code payload = %d", *recv_code);

  *entry = service_table[(*recv_code) % TABLE_SIZE];
  free0(recv_code);
  packet_header_t send_ack_header;
  if (*entry) {  // entry found
    (*entry)->receiver_fd = clientfd;
    status = create_header(&send_ack_header, kOpAck, kData, 0);
    if (status == -1) {
      error(clientfd, "fail creating ack header");
      free0(send_ack_header);
      return -1;
    }
    status = send(clientfd, send_ack_header, HEADER_LENGTH, 0);
    if (status == -1) {
      error(clientfd, "fail sending ack header");
      free0(send_ack_header);
      return -1;
    }

    packet_payload_t send_name_payload;
    int payload_len = create_payload(&send_name_payload, 0,
                                     (*entry)->name_length, (*entry)->name);
    if ((status = payload_len) <= 0) {
      error(clientfd, "fail creating name payload");
      free0(send_name_payload);
      return -1;
    }
    status = send(clientfd, send_name_payload, payload_len, 0);
    if (status <= 0) {
      error(clientfd, "fail sending name payload");
      free0(send_name_payload);
      return -1;
    }
    free0(send_name_payload);
  } else {  // entry not found
    status = create_header(&send_ack_header, kOpError, kNone, 0);
    if (status <= 0) {
      error(clientfd, "fail creating error ack header");
      free0(send_ack_header);
      return -1;
    }
    status = send(clientfd, send_ack_header, HEADER_LENGTH, 0);
    if (status <= 0) {
      error(clientfd, "fail sending error ack header");
      free0(send_ack_header);
      return -1;
    }
    error(clientfd, "recv code not found");
    status = -1;
  }
  free0(send_ack_header);
  return status;
}

static int bypass_packet(service_entry_t *entry, int sender_to_receiver,
                         int has_payload, int *transmit_finish) {
  struct timespec tt1, tt2;
  clock_gettime(CLOCK_REALTIME, &tt1);
  while (entry->sender_fd == -1 || entry->receiver_fd == -1) {
    clock_gettime(CLOCK_REALTIME, &tt2);
    if (tt2.tv_sec - tt1.tv_sec > TIMEOUT_SEC) {
      error(entry->sender_fd, "sender timout for waiting receiver");
      return -1;
    }
    usleep(1000);
  }
  int status = 0;
  long send_fd = (sender_to_receiver) ? entry->sender_fd : entry->receiver_fd;
  long recv_fd = (sender_to_receiver) ? entry->receiver_fd : entry->sender_fd;
  packet_header_t data_header = entry->header_buffer;

  int header_length = recv(send_fd, data_header, HEADER_LENGTH, 0);
  if ((status = header_length) <= 0) {
    error(send_fd, "fail receiving data header");
    goto BYPASS_RET;
  }
  send(recv_fd, data_header, HEADER_LENGTH, 0);
  if (transmit_finish != NULL) {
    *transmit_finish = (get_opcode(data_header) == kOpFin);
  }
  int data_len = get_payload_length(data_header);

  if (has_payload) {
    int payload_buf_len = GET_PAYLOAD_PACKET_LEN(data_len);
    packet_payload_t payload_buffer = entry->payload_buffer;
    int payload_len = retry_recv(send_fd, payload_buffer, payload_buf_len, 0);
    if ((status = payload_len) <= 0) {
      error(send_fd, "fail receiving data payload");
      goto BYPASS_RET;
    }
    status = retry_send(recv_fd, payload_buffer, payload_len, 0);
  }
BYPASS_RET:
  if (status <= 0) {
    packet_header_t err_header;
    create_header(&err_header, kOpError, kNone, 0);
    send(recv_fd, err_header, HEADER_LENGTH, 0);
    free0(err_header);
  }
  return status;
}

static int pubkey_transmission_handler(service_entry_t *entry) {
  int status;
  // pubkey
  status = bypass_packet(entry, 0, 1, NULL);
  if (status <= 0) {
    error(entry->receiver_fd, "receiver send public key failed");
    return -1;
  }
  // ack
  status = bypass_packet(entry, 1, 1, NULL);
  if (status <= 0) {
    error(entry->sender_fd, "sender ack public key failed");
    return -1;
  }
  return status;
}

int data_transmission_handler(service_entry_t *entry) {
  int status = 0;
  int is_finished = 0;
  info(entry->sender_fd, "start sending data");
  while (1) {
    // data
    status = bypass_packet(entry, 1, 1, &is_finished);
    if (status <= 0) {
      error(entry->sender_fd, "data transmission failed");
      break;
    }
    // ack
    if (is_finished) {
      info(entry->sender_fd, "data transmission finished");
      status = bypass_packet(entry, 0, 0, NULL);
      if (status <= 0) {
        error(entry->receiver_fd, "ack transmission failed");
      }
      break;
    }
  }
  return status;
}

static void *serve(void *argp) {
  long clientfd = (long)argp;
  // do something
  int status = 0;
  packet_header_t recv_header = malloc(HEADER_LENGTH);
  status = recv(clientfd, recv_header, HEADER_LENGTH, 0);
  if (status <= 0) {
    error(clientfd, "invalid packet header");
    return 0;
  }
  if (get_opcode(recv_header) == kOpCreate) {  // sender request

    // handler send file intention
    service_entry_t *working_entry;
    status = send_intention_handler(&working_entry, clientfd,
                                    get_payload_length(recv_header));
    if (status == -1) {
      error(clientfd, "handle sender intention failed");
      goto FINISH_SERVING;
    }

    // wait until receiver public key delivered
    status = pubkey_transmission_handler(working_entry);
    if (status == -1) {
      error(clientfd, "handle pubkey intention failed");
      goto FINISH_SERVING;
    }

    // send data from sender
    status = data_transmission_handler(working_entry);
    if (status == -1) {
      error(clientfd, "handle data sending failed");
      goto FINISH_SERVING;
    }

  FINISH_SERVING:
    pthread_mutex_lock(&mutex);
    if (working_entry != NULL) {
      int code = working_entry->code;
      if (working_entry->sender_fd > 0) close(working_entry->sender_fd);
      if (working_entry->receiver_fd > 0) close(working_entry->receiver_fd);
      free0(working_entry->name);
      free0(working_entry->header_buffer);
      free0(working_entry->payload_buffer);
      free0(working_entry);
      service_table[code % TABLE_SIZE] = NULL;
      occupy_count--;
    }
    pthread_mutex_unlock(&mutex);
  } else if (get_opcode(recv_header) == kOpRequest) {  // receiver request
    service_entry_t *working_entry;
    status = receiver_request_handler(&working_entry, clientfd);
    if (status == -1) {
      error(clientfd, "handle receive intention failed");
      return 0;
    }
    debug(clientfd, "receiver request update successfully");
  } else {  // invalid situation
    error(clientfd, "invalid header opcode: %d", get_opcode(recv_header));
    return 0;
  }
  free0(recv_header);
  return 0;
}

static void help() {
  printf("%-12s %-16s %-20s\n", "-h", "--help", "show this message");
  printf("%-12s %-16s %-20s\n", "-p [port]", "--port [port]",
         "specify server port, default: 8700");
}

int main(int argc, char *argv[]) {
  char *server_port = "8700";
  const char optstr[] = "hp:";
  const static struct option long_options[] = {
      {"help", no_argument, 0, 'h'}, {"port", optional_argument, 0, 'p'}};
  while (1) {
    int c = getopt_long(argc, argv, optstr, long_options, NULL);
    if (c == -1) break;
    switch (c) {
      case 'h':
        printf("CASend Server\n");
        help();
        return 0;
      case 'p':
        server_port = argv[optind - 1];
        break;
      default:
        help();
        return -1;
    }
  }

  int listenfd __attribute__((unused)) = open_listenfd(server_port);
  if (listenfd == -1) {
    fatal(0, "Unable to open server port: %s", server_port);
  }
  info(0, "listening on the port %s", server_port);

  pthread_mutex_init(&mutex, NULL);
  for (int i = 0; i < TABLE_SIZE; ++i) {
    service_table[i] = NULL;
  }
  while (1) {
    struct sockaddr client_info;
    socklen_t addrlen = 32;
    long clientfd = accept(listenfd, &client_info, &addrlen);
    if (clientfd == -1) continue;
    pthread_t thread;
    pthread_create(&thread, NULL, serve, (void *)clientfd);
    info(clientfd, "serving thread %ld created", (long)thread);
  }
  pthread_mutex_destroy(&mutex);

  return 0;
}
