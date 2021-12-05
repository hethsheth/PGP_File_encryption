#ifndef _AES_HPP
#define _AES_HPP

#include <openssl/evp.h>
#include <bits/stdc++.h>
#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define AES_128_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define BUFSIZE 4096

typedef struct cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

typedef struct enc{
	unsigned char *key;
	unsigned char *iv;
    char *encrypted_content_filename;
}enc;

void cleanup(FILE *ifp, FILE *ofp);
// unsigned long file_size(char *filename);
// string unsigned_char_to_string(unsigned char *out_buf, int out_len);
void print_hex(unsigned char *str, int len);
void aes_encrypt_decrypt(cipher_params_t *params, char *ifn, char *ofn);
enc* aes_encrypt(char *ifn);
void aes_decrypt(enc *enc_params, char *ofn);

#endif