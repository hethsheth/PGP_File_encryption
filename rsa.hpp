#ifndef _RSA_HPP
#define _RSA_HPP

#define AES_128_KEY_SIZE 16
#define RSA_ENCRYPT_SIZE 512

void print_hex2(unsigned char *str, int len);
unsigned char * rsa_encrypt(unsigned char *session_key, FILE *rsa_pub_key_file);
unsigned char * rsa_decrypt(unsigned char *ek, FILE *rsa_priv_key_file);
int sign(char *ifn, char *ofn, FILE *rsa_priv_key_file);

#endif