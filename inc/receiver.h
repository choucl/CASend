#ifndef _RECEIVER_H
#define _RECEIVER_H

#include <stdio.h>
#include <stdlib.h>

int recv_intention(int receiver_fd, char *input_code);
int recv_fname(int receiver_fd, char **fname);
int send_pub_key(int receiver_fd, char *pub_key, size_t pub_len, size_t *fsize);
int request_transfer(int receiver_fd, char *input_code, char **fname,
                     size_t *fsize, char *pub_key, size_t pub_len);
int receive_data(int receiver_fd, FILE *dst_file, int *encrypt_on);
int postprocess_file(FILE *tmp_file, char *fname, char *directory,
                     char *pri_key, size_t pri_len, char sha256_str[65],
                     int num_thread, size_t *ptext_fsize, int encrypt_on);
int compare_checksum(int receiver_fd, char sha256_str[65]);
int receive_handler(int argc, char *argv[]);

#endif  // _RECEIVER_H
