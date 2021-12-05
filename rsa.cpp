#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "rsa.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>

using namespace std;

unsigned long file_size2(char *filename)
{
	FILE *pFile = fopen(filename, "rb");
	fseek (pFile, 0, SEEK_END);
	unsigned long size = ftell(pFile);
	fclose (pFile);
	return size;
}

void print_hex2(unsigned char *str, int len){
	for (int i = 0; i < len; ++i)
	{
		printf("%02X ", str[i]);
	}
	printf("\n");
}

unsigned char * rsa_encrypt(unsigned char *session_key, FILE *rsa_pub_key_file){
	
	RSA *rsa_public_key = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();
	unsigned char *ek;
	size_t eklen, inlen;

	if (!PEM_read_RSA_PUBKEY(rsa_pub_key_file, &rsa_public_key, NULL, NULL)) {
		fprintf(stderr, "Error reading RSA Public Key File.\n");
		ERR_print_errors_fp(stderr);
		fclose(rsa_pub_key_file);
		return NULL;
	}

	if (!EVP_PKEY_assign_RSA(pkey, rsa_public_key)) {
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		fclose(rsa_pub_key_file);
		return NULL;
	}

	unsigned char *encrypted_input = (unsigned char*)malloc(RSA_size(rsa_public_key));	
	int encrypted_len = RSA_public_encrypt(AES_128_KEY_SIZE, session_key, encrypted_input, rsa_public_key, RSA_PKCS1_OAEP_PADDING);
	
	fclose(rsa_pub_key_file);
	return encrypted_input;
}

unsigned char * rsa_decrypt(unsigned char *ek, FILE *rsa_priv_key_file){
	RSA *rsa_private_key = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();
	unsigned char *dk;
	size_t dklen, inlen;

	if (!PEM_read_RSAPrivateKey(rsa_priv_key_file, &rsa_private_key, NULL, NULL)) {
		fprintf(stderr, "Error reading RSA Private Key File.\n");
		ERR_print_errors_fp(stderr);
	}

	if (!EVP_PKEY_assign_RSA(pkey, rsa_private_key)) {
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
	}

	unsigned char *decrypted_input = (unsigned char*)malloc(RSA_size(rsa_private_key));		
	int decrypted_len = RSA_private_decrypt(RSA_size(rsa_private_key), ek, decrypted_input, rsa_private_key, RSA_PKCS1_OAEP_PADDING);

	if(decrypted_len==-1){
		fprintf(stderr, "ERROR: EVP_CipherInit_ex failed1. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
	}

	fclose(rsa_priv_key_file);
	return decrypted_input;
}

int sign(char *ifn, char *ofn, FILE *rsa_priv_key_file){
	FILE *ifp, *ofp;

	unsigned long ifs = file_size2(ifn);
	// cout << ifs << endl;

	ifp = fopen(ifn, "rb");
	if (!ifp) {
		/* Unable to open file for writing */
		fprintf(stderr, "ERROR: rsa_sign input fopen error: %s\n", strerror(errno));
		return -1;
	}

	ofp = fopen(ofn, "wb");
	if (!ofp) {
		/* Unable to open file for writing */
		fprintf(stderr, "ERROR: rsa_sign output fopen error: %s\n", strerror(errno));
		fclose(ifp);
		return -1;
	}

	// Calculate SHA256 digest for ifp
	static unsigned char buffer[RSA_ENCRYPT_SIZE];
	unsigned bytes = 0;

	// Buffer to hold the calculated digest
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
 
	// Read data in chunks and feed it to OpenSSL SHA256
	while((bytes = fread(buffer, 1, RSA_ENCRYPT_SIZE, ifp)))
	{
		SHA256_Update(&ctx, buffer, bytes);
	}
 
	SHA256_Final(digest, &ctx);

	// for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
	// {
	// 	printf("%02X ", digest[i]);
	// }
	// printf("\n"); 

	RSA *rsa_private_key = NULL;
	if (!PEM_read_RSAPrivateKey(rsa_priv_key_file, &rsa_private_key, NULL, NULL)) {
		fprintf(stderr, "Error reading RSA Private Key File.\n");
		ERR_print_errors_fp(stderr);
	}

	unsigned char *sig = NULL;
	unsigned int sig_len = 0;

	sig = (unsigned char *)malloc(RSA_size(rsa_private_key));

	// cout << RSA_size(rsa_private_key) << " " << SHA256_DIGEST_LENGTH << endl;

	if(RSA_sign(NID_sha1, digest, sizeof digest, sig, &sig_len, rsa_private_key)!=1){
		fprintf(stderr, "Error reading RSA Private Sender Key File.\n");
		ERR_print_errors_fp(stderr);
	}

	fwrite(sig, sizeof(unsigned char), sig_len, ofp);

	// for (int i = 0; i < sig_len; ++i)
	// {
	// 	printf("%02X ", sig[i]);
	// }
	// printf("\n"); 

	char ch;
	rewind(ifp);
    for (int i = 0; i < ifs; ++i)
    {
        ch = fgetc(ifp);
        fputc(ch, ofp);
    }

    fclose(ifp);
    fclose(ofp);
	
	fclose(rsa_priv_key_file);
	// cout << sig_len << " " << file_size2(ofn) << endl;
	return 0;
}

bool verify(char *ifn, char *ofn, FILE *rsa_pub_key_file){
	FILE *ifp, *ofp;

	unsigned long ifs = file_size2(ifn);
	// cout << ifs << endl;

	ifp = fopen(ifn, "rb");
	if (!ifp) {
		/* Unable to open file for writing */
		fprintf(stderr, "ERROR: rsa_sign input fopen error: %s\n", strerror(errno));
		return -1;
	}

	ofp = fopen(ofn, "wb");
	if (!ofp) {
		/* Unable to open file for writing */
		fprintf(stderr, "ERROR: rsa_sign output fopen error: %s\n", strerror(errno));
		fclose(ifp);
		return -1;
	}

	// Calculate SHA256 digest for ifp
	static unsigned char buffer[RSA_ENCRYPT_SIZE];
	unsigned bytes = 0, bytes1 = 0;

	unsigned char *sig = NULL;
	unsigned int sig_len = RSA_ENCRYPT_SIZE;

	sig = (unsigned char *)malloc(RSA_ENCRYPT_SIZE);
	bytes1 = fread(sig, 1, RSA_ENCRYPT_SIZE, ifp);

	// for (int i = 0; i < sig_len; ++i)
	// {
	// 	printf("%02X ", sig[i]);
	// }
	// printf("\n");

 //    cout << bytes1 << endl;

    // Buffer to hold the calculated digest
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
 	int x = 0;
    // Read data in chunks and feed it to OpenSSL SHA256
    while((bytes = fread(buffer, 1, RSA_ENCRYPT_SIZE, ifp)))
    {
        x+=bytes;
        fwrite(buffer, sizeof(unsigned char), bytes, ofp);
        // cout << buffer << endl;
        SHA256_Update(&ctx, buffer, bytes);
    }
    // cout << "x: " << x << endl;
 
    SHA256_Final(digest, &ctx);

 //    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
	// {
	// 	printf("%02X ", digest[i]);
	// }
	// printf("\n");
    // fclose(ifp);
 
    
    RSA *rsa_public_key = NULL;
	if (!PEM_read_RSA_PUBKEY(rsa_pub_key_file, &rsa_public_key, NULL, NULL)) {
		fprintf(stderr, "Error reading RSA Public Key File.\n");
		ERR_print_errors_fp(stderr);
	}
 

 	// cout << RSA_size(rsa_public_key) << endl;
    // Decrypt signature (in buffer) and verify it matches
    // with the digest calculated from data file.
    int result = RSA_verify(NID_sha256, digest, sizeof digest, sig, bytes1, rsa_public_key);

    fclose(ifp);
    fclose(ofp);
	
	fclose(rsa_pub_key_file);
	// cout << file_size2(ofn) << endl;
	
	return true;
}