#ifndef _RSA_H
#define _RSA_H

#include <stdlib.h>

#define MAX_PTEXT_CHUNK_LEN 214
#define CTEXT_CHUNK_LEN 256

// Generate RSA public / private key pairs
// arguments:
//   - unallocated char ** to store keys
//   - size_t pointers to store key lengths
// return value:
//   - -1: key gen failed
//   - 1: key gen successfully
int generate_keys(char **pub_key, char **pri_key, size_t *pri_len,
                  size_t *pub_len);

// Encrypt a message using a public key and return the ciphertext
// argumets:
//   - ptext_len: length of plain text
//   - ctext_len: buffer to get the cipher text length
// return value:
//   - NULL: encryption failed
//   - otherwise: ciphertext
unsigned char *encrypt(char *pub_key, size_t pub_len,
                       const unsigned char *ptext, size_t ptext_len,
                       size_t *ctext_len);

// Decrypt a ciphertext using a private key and return the plaintext
// argumets:
//   - ctext_len: length or cipher text
//   - ptext_len: buffer to get the plain text length
// return value:
//   - NULL: decryption failed
//   - otherwise: plaintext
unsigned char *decrypt(char *pri_key, size_t pri_len,
                       const unsigned char *ctext, size_t ctext_len,
                       size_t *ptext_len);
#endif
