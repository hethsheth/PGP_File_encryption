#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "aes.hpp"
#include "rsa.hpp"
#include "compress.hpp"

using namespace std;

void write_to_file(unsigned char *iv, unsigned char *e_key, char *encrypted_content_filename, char *encrypted_filename){
	
    int ifs = file_size(encrypted_content_filename);
    
    FILE *encrypted_content, *encrypted_file;
    encrypted_content = fopen(encrypted_content_filename, "rb");
    if (!encrypted_content) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return;
    }

    encrypted_file = fopen(encrypted_filename, "wb");
    if (!encrypted_file) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        fclose(encrypted_content);
        return;
    }

	int num_written;
    num_written = fwrite(iv, 1, AES_BLOCK_SIZE, encrypted_file);
    num_written = fwrite(e_key, 1, RSA_ENCRYPT_SIZE, encrypted_file);

    char ch;
    for (int i = 0; i < ifs; ++i)
    {
        ch = fgetc(encrypted_content);
        fputc(ch, encrypted_file);
    }

    fclose(encrypted_content);
    fclose(encrypted_file);
}

enc * read_from_file(char *encrypted_filename){

    int ifs =  file_size(encrypted_filename);
    
    FILE *encrypted_content, *encrypted_file;
    encrypted_file = fopen(encrypted_filename, "rb");
    if (!encrypted_file) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return NULL;
    }


	enc *enc_params = (enc *)malloc(sizeof(enc));
    if (!enc_params) {
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return NULL;
    }

    int num_read;

    unsigned char *iv = (unsigned char *)malloc(AES_BLOCK_SIZE*sizeof(unsigned char));
    num_read = fread(iv, 1, AES_BLOCK_SIZE, encrypted_file);
    ifs -= AES_BLOCK_SIZE;
    enc_params->iv = iv;
    
    unsigned char *e_key = (unsigned char *)malloc(RSA_ENCRYPT_SIZE*sizeof(unsigned char));
    num_read = fread(e_key, 1, RSA_ENCRYPT_SIZE, encrypted_file);
    ifs -= RSA_ENCRYPT_SIZE;
    enc_params->key = e_key;

    encrypted_content = fopen("encrypted_content_d", "wb");
    if (!encrypted_content) {
        fprintf(stderr, "ERROR: fopen error0: %s\n", strerror(errno));
        return NULL;
    }

    char ch;
    for (int i = 0; i < ifs; ++i)
    {
        ch = fgetc(encrypted_file);
        fputc(ch, encrypted_content);
    }
    
    fclose(encrypted_content);
    fclose(encrypted_file);
    enc_params->encrypted_content_filename = (char *)"encrypted_content_d";
    return enc_params;
}

int encrypt_file(char *input_filename, char *output_filename, char *rsa_encryption_key, char *rsa_signature_key){

    FILE *rsa_key_file = fopen(rsa_signature_key, "rb");
    if (!rsa_key_file) {
        perror(rsa_signature_key);
        fprintf(stderr, "Error1 loading PEM RSA Public Key File.\n");
        exit(1);
    }

    // Signature
    char *signed_filename = (char *)"signed_file";
    sign(input_filename, signed_filename, rsa_key_file);
    cout << "SIGNATURE SUCCESSFUL\n";

    // ZIP Compression
    char *compressed_filename = (char *)"compressed_file";
    compress_one_file(signed_filename, compressed_filename);
    cout << "ZIP COMPRESSION SUCCESSFUL\n";

    // AES Encryption
    enc *enc_params = (enc *)malloc(sizeof(enc));
    if (!enc_params) {
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }
    
    enc_params = aes_encrypt(compressed_filename);
    cout << "AES ENCRYPT SUCCESSFUL\n";

    // RSA Encryption of session key
    FILE *rsa_pkey_file = fopen(rsa_encryption_key, "rb");
    if (!rsa_pkey_file) {
        perror(rsa_encryption_key);
        fprintf(stderr, "Error1 loading PEM RSA Public Key File.\n");
        exit(1);
    }
    unsigned char *e_key = (unsigned char *)malloc(512*sizeof(unsigned char));
    e_key = rsa_encrypt(enc_params->key, rsa_pkey_file);
    cout << "RSA ENCRYPT SUCCESSFUL\n";    

    // IV+Encrypted Key+Encrypted file contents to Output file
    write_to_file(enc_params->iv, e_key, enc_params->encrypted_content_filename, output_filename);
    cout << "WRITE TO FILE SUCCESSFUL\n";

    remove(signed_filename);
    remove(compressed_filename);
    remove(enc_params->encrypted_content_filename);

    return 1;
}

int decrypt_file(char *input_filename, char *output_filename, char *rsa_encryption_key, char *rsa_signature_key){
    
    // Read from encrypted file
    enc *enc_params = (enc *)malloc(sizeof(enc));
    if (!enc_params) {
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }
    enc_params = read_from_file(input_filename);
    cout << "READ FROM FILE SUCCESSFUL\n";

    // Decrypt session key - RSA
    FILE *rsa_key_file = fopen(rsa_encryption_key, "rb");
    if (!rsa_key_file) {
        perror(rsa_encryption_key);
        fprintf(stderr, "Error2 loading PEM RSA Private Key File.\n");
        exit(1);
    }
    unsigned char *d_key = (unsigned char *)malloc(512*sizeof(unsigned char));
    d_key = rsa_decrypt(enc_params->key, rsa_key_file);
    cout << "RSA DECRYPT SUCCESSFUL\n";
    
    // AES Decryption
    enc_params->key = d_key;
    char *compressed_filename = (char *)"compressed_file";
    aes_decrypt(enc_params, compressed_filename);
    cout << "AES DECRYPT SUCCESSFUL\n";

    // ZIP Decompression
    char *signed_filename = (char *)"signed_file";
    decompress_one_file(compressed_filename, signed_filename);
    cout << "ZIP DECOMPRESSION SUCCESSFUL\n";

    // cout << file_size(signed_filename) << endl;

    // Verification
    FILE *rsa_pkey_file = fopen(rsa_signature_key, "rb");
    if (!rsa_pkey_file) {
        perror(rsa_signature_key);
        fprintf(stderr, "Error1 loading PEM RSA Public Key File.\n");
        exit(1);
    }

    bool verified = verify(signed_filename, output_filename, rsa_pkey_file);
    if(!verified){
        fprintf(stderr, "Error verifying signature.\n");
    }
    else cout << "SIGNATURE VERIFIED\n";

    remove(signed_filename);
    remove(compressed_filename);
    remove(enc_params->encrypted_content_filename);
    return 1;
}

int main(int argc, char *argv[]) {
    

    /* Make sure user provides the input file */
    if (argc < 4) {
		fprintf(stderr, "Usage: %s <Mode {encrypt, decrypt} <Input Filename> <Encrypted/Decrypted Output Filename> <Public key filename (receiver/sender)> <Private key filename (sender/receiver)> \n", argv[0]);
		exit(1);
	}

    if(strcmp(argv[1], "encrypt")==0){
        encrypt_file(argv[2], argv[3], argv[4], argv[5]);
    }

    else if(strcmp(argv[1], "decrypt")==0){
        decrypt_file(argv[2], argv[3], argv[4], argv[5]);
    }

    else{
        printf("Please select encrypt/decrypt\n");
    }

    return 0;
}