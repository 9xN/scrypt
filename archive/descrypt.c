#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* copy paste scrypt output here */
unsigned char shellcode[] = { "\xe6\xaa\x39\x1a\x2c\xab\x93\x7d\xd7\x84\xef\x22\x28\x6e\x25\x13\x5c\x86\xeb\xd7\x1d\x78\x57\x7d\x89\xcc\x2a\x9e\xc5\x42\x72\xa0\x0f\x25\x5c\x1f\x95\xe2\x1b\x79\x66\x0f\xe6\x0d\x6a\xdf\x42\x11\x9e\xcd\x5d\x45\x08\x42\xbe\xfa\x4a\x89\x13\xa1\x92\x01\xfc\x88\xf6\x66\x50\x5b\xb9\x82\x32\x95\xe3\x83\x46\x77\xb4\x4d\x33\xba" };
unsigned char aeskey[] = { "\x8c\x8d\x5b\x0b\x14\xc7\xf5\x1c\x39\x13\xd8\x06\x7f\x96\xcb\x1c\xfd\x6e\x9a\xac\x1d\xbd\xc2\x6c\xb1\xa0\x3f\x6f\x72\xab\x8b\x6e\x71\x17\xb7\x2c\xa5\x9f\xcf\x8d\x93\x96\x72\xc0\x36\x89\x67\x53\x6c\x08\x7e\x89\x3b\x19\x28\x01\x37\xb7\x8e\x79\x27\x2f\x52\x6c" };
unsigned char iv[] = { "\x8c\x85\xf3\xcf\x8e\x33\x0e\xe5\x52\x44\x15\xce\xd2\x71\x79\x11" };
unsigned char xorkey[] = { "\x5f\x7e\x84\x6f\xc9\x2a\xd1\x6f\x79\xe4\x78\xbe\xf6\x7d\x19\x23\x3d\xc1\xea\xe1\xf5\xef\xc7\xcf\x31\xe1\x40\xc6\x41\xf8\xc4\xa0\x76\x48\x0f\x40\x72\xe1\xaf\xec\xc5\x27\xaa\xbc\xa4\xc3\xdf\xe2\x84\xc9\xc3\x79\xb8\x8a\x49\xe9\x6b\x89\xaf\xac\x81\x73\x4c\xf8\xbb\x5c\x38" };
int rot = 3;
int dec = 254;
int iterations = 5;
/* ------------------ */

const char *RED = "\033[01;31m";
const char *GRE = "\033[01;32m";
const char *YEL = "\033[01;33m";
const char *BLU = "\033[01;34m";
const char *MAG = "\033[01;35m";
const char *CYA = "\033[01;36m";
const char *RES = "\033[0m";

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
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aeskey, iv);
    EVP_DecryptUpdate(ctx, plaintext, plaintext_len, ciphertext, ciphertext_len);
    EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_len, &len);
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