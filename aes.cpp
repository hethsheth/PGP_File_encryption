#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "aes.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <arpa/inet.h>

using namespace std;

void print_hex(unsigned char *str, int len){
	for (int i = 0; i < len; ++i)
	{
		printf("%02X ", str[i]);
	}
    printf("\n");
}

void cleanup(FILE *ifp, FILE *ofp){
    fclose(ifp);
    fclose(ofp);
}

void aes_encrypt_decrypt(cipher_params_t *params, char *ifn, char *ofn){

    FILE *ifp, *ofp;

    ifp = fopen(ifn, "rb");
    if (!ifp) {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: aes_encrypt_decrypt input fopen error: %s\n", strerror(errno));
        return;
    }

    ofp = fopen(ofn, "wb");
    if (!ofp) {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: aes_encrypt_decrypt output fopen error: %s\n", strerror(errno));
        fclose(ifp);
        return;
    }
    
    /* Allow enough space in output buffer for additional block */
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    /* Check lengths of key, IV */
    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_128_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);

    /* Set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
    }

    while(1){
        // Read in data in blocks until EOF. Update the ciphering with each read.
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        if (ferror(ifp)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);    
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);    
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        if (ferror(ofp)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);    
        }
        if (num_bytes_read < BUFSIZE) {
            /* Reached End of file */
            break;
        }
    }

    /* Now cipher the final block and write it out to file */
    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. %d : OpenSSL error: %s\n", out_len, ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
    }
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    if (ferror(ofp)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
    cleanup(ifp, ofp);
}

enc* aes_encrypt(char *ifn){

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if (!params) {
        /* Unable to allocate memory on heap*/
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return NULL;
    }

    /* Key to use for encrpytion and decryption */
    unsigned char *key = (unsigned char *)malloc(AES_128_KEY_SIZE*sizeof(unsigned char));
    
    /* Initialization Vector */
    unsigned char *iv = (unsigned char *)malloc(AES_BLOCK_SIZE*sizeof(unsigned char));

    /* Generate cryptographically strong pseudo-random bytes for key and IV */
    if (!RAND_bytes(key, AES_128_KEY_SIZE) || !RAND_bytes(iv, AES_BLOCK_SIZE)) {
        /* OpenSSL reports a failure, act accordingly */
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return NULL;
    }

    params->key = key;
    params->iv = iv;
    params->encrypt = 1;
    params->cipher_type = EVP_aes_128_cbc();

    /* Encrypt the given file */
    aes_encrypt_decrypt(params, ifn, (char *)"aes_encrypted");

    enc *enc_params = (enc *)malloc(sizeof(enc));
    if (!enc_params) {
        /* Unable to allocate memory on heap*/
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return NULL;
    }
    
    enc_params->key = params->key;
    enc_params->iv = params->iv;
    enc_params->encrypted_content_filename = (char *)"aes_encrypted";

    return enc_params;
}

void aes_decrypt(enc *enc_params, char *ofn){

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if (!params) {
        // Unable to allocate memory on heap
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return;
    }

    /* Indicate that we want to decrypt */
    params->encrypt = 0;
    params->cipher_type = EVP_aes_128_cbc();
    params->key = enc_params->key;
    params->iv = enc_params->iv;

    /* Decrypt the given file */
    aes_encrypt_decrypt(params, enc_params->encrypted_content_filename, ofn);
}
