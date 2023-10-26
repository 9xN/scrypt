#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* copy paste scrypt output here */
unsigned char shellcode[] = {/* shellcode */};
unsigned char aeskey[] = {/* aes key */};
unsigned char iv[] = {/* aes iv */};
unsigned char xorkey[] = {/* xor key */};
int rot = /* rotation value */;
int dec = /* dec value*/;
int iterations = /* iterations value */;
/* ------------------ */

const char *RED = "\033[01;31m";
const char *GRE = "\033[01;32m";
const char *YEL = "\033[01;33m";
const char *BLU = "\033[01;34m";
const char *MAG = "\033[01;35m";
const char *CYA = "\033[01;36m";
const char *RES = "\033[0m";

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void print_banner() {
    printf("\033[38;5;16m \033[38;5;16m┌\033[38;5;16m┬\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┌\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┌\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┌\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┬\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┬\033[38;5;16m \033[38;5;16m┬\033[38;5;16m \033[38;5;16m┌\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┌\033[38;5;16m┬\033[38;5;16m┐\n\033[38;5;16m \033[38;5;16m \033[38;5;16m│\033[38;5;16m│\033[38;5;17m \033[38;5;17m├\033[38;5;17m┤\033[38;5;17m \033[38;5;17m \033[38;5;17m└\033[38;5;17m─\033[38;5;17m┐\033[38;5;17m \033[38;5;17m│\033[38;5;17m \033[38;5;17m \033[38;5;17m \033[38;5;17m├\033[38;5;17m┬\033[38;5;17m┘\033[38;5;17m \033[38;5;17m└\033[38;5;17m┬\033[38;5;17m┘\033[38;5;17m \033[38;5;17m├\033[38;5;17m─\033[38;5;17m┘\033[38;5;17m \033[38;5;17m \033[38;5;17m│\033[38;5;17m \n\033[38;5;17m \033[38;5;17m─\033[38;5;17m┴\033[38;5;17m┘\033[38;5;18m \033[38;5;18m└\033[38;5;18m─\033[38;5;18m┘\033[38;5;18m \033[38;5;18m└\033[38;5;18m─\033[38;5;18m┘\033[38;5;18m \033[38;5;18m└\033[38;5;18m─\033[38;5;18m┘\033[38;5;18m \033[38;5;18m┴\033[38;5;18m└\033[38;5;18m─\033[38;5;18m \033[38;5;18m \033[38;5;18m┴\033[38;5;18m \033[38;5;18m \033[38;5;18m┴\033[38;5;18m \033[38;5;18m \033[38;5;18m \033[38;5;18m \033[38;5;18m┴\033[38;5;18m \n");
    printf("%s~> %sMade by: %sgithub.com/9xN\n%s----------------------------%s\n%sDECODING/DECRYPTING SHELLCODE...\n", YEL, GRE, MAG, RED, RES, CYA);
}

void xor_encoding(unsigned char *shellcode, size_t length, unsigned char *xorkey, size_t key_length) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] ^= xorkey[i % key_length];
    }
}

void not_encoding(unsigned char *shellcode, size_t length) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] = ~shellcode[i];
    }
}

void rot_encoding(unsigned char *shellcode, size_t length, unsigned int rotation) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] = (shellcode[i] << rotation) | (shellcode[i] >> (8 - rotation));
    }
}

void dec_encoding(unsigned char *shellcode, size_t length, unsigned char decrement) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] -= decrement;
    }
}

void decrypt_aes_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *aeskey, unsigned char *iv, unsigned char *plaintext, int *plaintext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aeskey, iv))
        handleErrors();
    if (1 != EVP_DecryptUpdate(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len))
        handleErrors();
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &len))
        handleErrors();
    *plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

void format_and_print(unsigned char *shellcode, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("\\x%02x", shellcode[i]);
    }
}

int main() {
    print_banner();
    int i, shellcode_len = sizeof(shellcode), decrypted_length = shellcode_len, ciphertext_len = shellcode_len - 1, aeskey_length = sizeof(aeskey) - 1, xorkey_length = sizeof(xorkey) - 1;
    unsigned char decrypted_shellcode[shellcode_len];
    unsigned char *ciphertext = malloc(ciphertext_len);
    memcpy(ciphertext, shellcode, ciphertext_len);
    decrypt_aes_cbc(ciphertext, ciphertext_len, aeskey, iv, decrypted_shellcode, &decrypted_length);
    for (i = 0; i < iterations; i++) {
        dec_encoding(decrypted_shellcode, decrypted_length, -dec);
        rot_encoding(decrypted_shellcode, decrypted_length, 8 - rot);
        not_encoding(decrypted_shellcode, decrypted_length);
        xor_encoding(decrypted_shellcode, decrypted_length, xorkey, xorkey_length);
    }
    printf("SHELLCODE DECODED/DECRYPTED:%s\n%s", RES, RED);
    format_and_print(decrypted_shellcode, decrypted_length);
    free(ciphertext);
    return 0;
}
