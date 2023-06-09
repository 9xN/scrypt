#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    printf("\033[38;5;16m \033[38;5;16m┌\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┌\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┬\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┬\033[38;5;16m \033[38;5;16m┬\033[38;5;16m \033[38;5;16m┌\033[38;5;16m─\033[38;5;16m┐\033[38;5;16m \033[38;5;16m┌\033[38;5;16m┬\033[38;5;16m┐\n\033[38;5;16m \033[38;5;16m└\033[38;5;16m─\033[38;5;16m┐\033[38;5;17m \033[38;5;17m│\033[38;5;17m \033[38;5;17m \033[38;5;17m \033[38;5;17m├\033[38;5;17m┬\033[38;5;17m┘\033[38;5;17m \033[38;5;17m└\033[38;5;17m┬\033[38;5;17m┘\033[38;5;17m \033[38;5;17m├\033[38;5;17m─\033[38;5;17m┘\033[38;5;17m \033[38;5;17m \033[38;5;17m│\033[38;5;17m\n\033[38;5;17m \033[38;5;17m└\033[38;5;17m─\033[38;5;17m┘\033[38;5;18m \033[38;5;18m└\033[38;5;18m─\033[38;5;18m┘\033[38;5;18m \033[38;5;18m┴\033[38;5;18m└\033[38;5;18m─\033[38;5;18m \033[38;5;18m \033[38;5;18m┴\033[38;5;18m \033[38;5;18m \033[38;5;18m┴\033[38;5;18m \033[38;5;18m \033[38;5;18m \033[38;5;18m \033[38;5;18m┴\033[38;5;18m\n");
    printf("%s~> %sMade by: %sgithub.com/9xN\n%s----------------------------%s\n%sENCODING/ENCRYPTING SHELLCODE...\n", YEL, GRE, MAG, RED, RES, CYA);
}

unsigned char *readShellcodeFromFile(const char *filename, size_t *original_length) {
    FILE *file;
    unsigned char *shellcode = NULL;
    size_t file_size;
    file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open the file.\n");
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);
    shellcode = (unsigned char *)malloc(file_size);
    if (shellcode == NULL) {
        printf("Failed to allocate memory for shellcode.\n");
        fclose(file);
        return NULL;
    }
    size_t i = 0;
    char hexByte[3];
    char temp;
    while ((temp = fgetc(file)) != EOF) {
        if (temp == '"' || temp == '\n' || temp == '\0') {
            continue;
        }
        hexByte[0] = temp;
        hexByte[1] = fgetc(file);
        hexByte[2] = '\0';
        unsigned char byte = (unsigned char)strtol(hexByte, NULL, 16);
        if (byte != '\0') {
            shellcode[i] = byte;
            i++;
        }
    }
    fclose(file);
    *original_length = i;
    return shellcode;
}

void xor_encoding(unsigned char *shellcode, size_t length, unsigned char *xorkey, size_t xorkey_length) {
    for (size_t i = 0; i < length; i++) {
        shellcode[i] ^= xorkey[i % xorkey_length];
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

void sanitize_shellcode(unsigned char *shellcode, size_t *length) {
    unsigned char *sanitized = (unsigned char *)malloc(*length);
    size_t j = 0;
    for (size_t i = 0; i < *length; i++) {
        if (shellcode[i] != '\0') {
            sanitized[j++] = shellcode[i];
        }
    }
    *length = j;
    memcpy(shellcode, sanitized, *length);
    free(sanitized);
}

void encrypt_aes_cbc(unsigned char *plaintext, int plaintext_len, unsigned char *aeskey, unsigned char *iv, unsigned char *ciphertext, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aeskey, iv))
        handleErrors();
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len))
        handleErrors();
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_len, &len))
        handleErrors();
    *ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

void format_and_print(unsigned char *shellcode, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("\\x%02x", shellcode[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <shellcode_file> <num_iterations>\n", argv[0]);
        return 1;
    }
    print_banner();
    srand((unsigned int)time(NULL));
    char *filename = argv[1];
    size_t original_length;
    unsigned char *original_shellcode = readShellcodeFromFile(filename, &original_length);
    if (original_shellcode == NULL) {
        return 1;
    }
    int rot = rand() % 9, dec = rand() & 0xff, ciphertext_len, i;
    unsigned char *shellcode = (unsigned char *)malloc(original_length);
    memcpy(shellcode, original_shellcode, original_length);
    unsigned char *aeskey = (unsigned char *)malloc(EVP_MAX_KEY_LENGTH);
    unsigned char *iv = (unsigned char *)malloc(EVP_MAX_IV_LENGTH);
    RAND_bytes(aeskey, EVP_MAX_KEY_LENGTH);
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);
    unsigned char *ciphertext = (unsigned char *)malloc(original_length + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    unsigned char xorkey[original_length];
    for (size_t i = 0; i < original_length; i++) {
        xorkey[i] = rand() & 0xff;
    }
    size_t xorkey_length = sizeof(xorkey) / sizeof(xorkey[0]);
    sanitize_shellcode(shellcode, &original_length);
    for (i = 0; i < atoi(argv[2]); i++) {
        xor_encoding(shellcode, original_length, xorkey, xorkey_length);
        not_encoding(shellcode, original_length);
        rot_encoding(shellcode, original_length, rot);
        dec_encoding(shellcode, original_length, dec);
    }
    encrypt_aes_cbc(shellcode, original_length, aeskey, iv, ciphertext, &ciphertext_len);
    printf("%sSHELLCODE ENCODED/ENCRYPTED:%s\n%s[+]%s Shellcode Length: %s%zu %s~> %s%d\n", CYA, RES, BLU, GRE, RED, original_length, YEL, RED, ciphertext_len);
    printf("%sunsigned char%s shellcode[]%s = %s{ %s\"", MAG, RES, YEL, RES, RED);
    format_and_print(ciphertext, ciphertext_len);
    printf("\" %s};\n", RES);
    printf("%sunsigned char%s aeskey[]%s = %s{ %s\"", MAG, RES, YEL, RES, RED);
    format_and_print(aeskey, EVP_MAX_KEY_LENGTH);
    printf("\" %s};\n", RES);
    printf("%sunsigned char%s iv[]%s = %s{ %s\"", MAG, RES, YEL, RES, RED);
    format_and_print(iv, EVP_MAX_IV_LENGTH);
    printf("\" %s};\n", RES);
    printf("%sunsigned char%s xorkey[]%s = %s{ %s\"", MAG, RES, YEL, RES, RED);
    format_and_print(xorkey, sizeof(xorkey));
    printf("\" %s};\n", RES);
    printf("%sint%s rot%s = %s%d%s;\n", MAG, RES, YEL, RED, rot, RES);
    printf("%sint%s dec%s = %s%d%s;\n", MAG, RES, YEL, RED, dec, RES);
    printf("%sint%s iterations%s = %s%d%s;\n", MAG, RES, YEL, RED, atoi(argv[2]), RES);

    free(shellcode);
    free(aeskey);
    free(iv);
    free(ciphertext);
    return 0;
}