#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>

int generate_keys(char **pub_key, char **pri_key, size_t *pri_len,
                  size_t *pub_len) {
  EVP_PKEY_CTX *ctx;
  EVP_PKEY *pkey = NULL;

  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx) {
    fprintf(stderr, "Error: EVP_PKEY_CTX_new_id\n");
    return -1;
  }
  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    fprintf(stderr, "Error: EVP_PKEY_keygen_init\n");
    return -1;
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
    fprintf(stderr, "Error: EVP_PKEY_CTX_set_rsa_keygen_bits\n");
    return -1;
  }
  if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    fprintf(stderr, "Error: EVP_PKEY_keygen\n");
    return -1;
  }

  BIO *pri = BIO_new(BIO_s_mem());
  BIO *pub = BIO_new(BIO_s_mem());

  PEM_write_bio_PrivateKey(pri, pkey, NULL, NULL, 0, NULL, NULL);
  PEM_write_bio_PUBKEY(pub, pkey);

  *pri_len = BIO_pending(pri);
  *pub_len = BIO_pending(pub);

  *pri_key = malloc(*pri_len);
  *pub_key = malloc(*pub_len);

  BIO_read(pri, *pri_key, *pri_len);
  BIO_read(pub, *pub_key, *pub_len);

  // Free the EVP_PKEY structure
  EVP_PKEY_free(pkey);
  return 1;
}

// Encrypt a message using a public key and return the ciphertext
unsigned char *encrypt(char *pub_key, size_t pub_len, const unsigned char *msg,
                       size_t msg_len, size_t *ctext_len) {
  BIO *pub = BIO_new(BIO_s_mem());
  EVP_PKEY_CTX *ctx;
  unsigned char *out;
  size_t outlen;

  BIO_write(pub, pub_key, pub_len);
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(pub, NULL, NULL, NULL);
  if (!pkey) {
    fprintf(stderr, "Error: PEM_read_PUBKEY\n");
    return NULL;
  }
  ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx) {
    fprintf(stderr, "no ctx\n");
    return NULL;
  }
  if (EVP_PKEY_encrypt_init(ctx) <= 0) {
    fprintf(stderr, "EVP_PKEY_encrypt_init\n");
    return NULL;
  }
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding\n");
    return NULL;
  }

  /* Determine buffer length */
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, msg, msg_len) <= 0) {
    fprintf(stderr, "EVP_PKEY_encrypt\n");
    return NULL;
  }
  out = OPENSSL_malloc(outlen);

  if (!out) {
    fprintf(stderr, "Error: malloc failure\n");
    return NULL;
  }

  if (EVP_PKEY_encrypt(ctx, out, &outlen, msg, msg_len) <= 0) {
    fprintf(stderr, "EVP_PKEY_encrypt\n");
    return NULL;
  }
  *ctext_len = outlen;

  EVP_PKEY_free(pkey);
  return out;
}

// Decrypt a ciphertext using a private key and return the plaintext
unsigned char *decrypt(char *pri_key, size_t pri_len,
                       const unsigned char *ctext, size_t len) {
  BIO *pri = BIO_new(BIO_s_mem());
  EVP_PKEY_CTX *ctx;
  unsigned char *out;
  size_t outlen;

  BIO_write(pri, pri_key, pri_len);
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(pri, NULL, NULL, NULL);
  if (!pkey) {
    fprintf(stderr, "Error: PEM_read_bio_PrivateKey\n");
    return NULL;
  }

  ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!ctx) {
    fprintf(stderr, "Error: malloc failure\n");
    return NULL;
  }
  if (EVP_PKEY_decrypt_init(ctx) <= 0) {
    fprintf(stderr, "EVP_PKEY_decrypt_init");
    return NULL;
  }
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding");
    return NULL;
  }

  /* Determine buffer length */
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ctext, len) <= 0) {
    fprintf(stderr, "EVP_PKEY_decrypt 1");
    return NULL;
  }
  out = OPENSSL_malloc(outlen);
  if (!out) {
    fprintf(stderr, "Error: malloc failure\n");
    return NULL;
  }
  if (EVP_PKEY_decrypt(ctx, out, &outlen, ctext, len) <= 0) {
    fprintf(stderr, "EVP_PKEY_decrypt 2");
    return NULL;
  }

  EVP_PKEY_free(pkey);
  return out;
}
