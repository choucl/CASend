#ifndef _SENDER_H
#define _SENDER_H

#include <stdio.h>
#include <stdlib.h>

static void help();
static void *timer(void *argp);
size_t get_fsize(char *fname);
int send_intention(int sender_fd, char *pub_key, size_t pub_len);
int recv_code(int sender_fd, int *code, char *pri_key, size_t pri_len);
int send_fname(int sender_fd, char *fname);
int register_new_transfer(int sender_fd, char *fname, char *pub_key,
                          size_t pub_len, char *pri_key, size_t pri_len);
int receive_pub_key(int sender_fd, char *fname, char **pub_key, size_t *pub_len,
                    size_t *fsize, size_t *send_fsize, int encrypt_on);
int preprocess_file(char *fname, FILE *dst_file, char *pub_key, size_t pub_len,
                    char sha256_str[65], int encrypt_on, int num_thread);
int send_data(int sender_fd, FILE *src_file, int encrypt_on);
int send_checksum(int sender_fd, char sha256_str[65]);
int send_handler(int argc, char *argv[]);

#endif  // _SENDER_H
