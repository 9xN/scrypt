#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../common/aes.h"
#include "../common/aes.c"

#define MAX_SIZE (4ULL * 1024 * 1024 * 1024)

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
    struct AES_ctx ctx;
    AES256CBC_init_ctx_iv(&ctx, aeskey, iv);
    AES256CBC_encrypt(&ctx, plaintext, plaintext_len);
    *ciphertext_len = plaintext_len;
}

// void convertShellcode(const char* shellcode, unsigned char* data, int dataSize) {
//     int shellcodeLength = strlen(shellcode) / 4; // Each \x is 4 characters

//     // Initialize the data array with zeros
//     memset(data, 0, dataSize);

//     // Convert the shellcode into bytes
//     for (int i = 0; i < shellcodeLength; i++) {
//         sscanf(shellcode + i * 4, "\\x%02hhx", &data[i]);
//     }
// }

// void pad_and_format_print(unsigned char *shellcode, size_t originalSize) {
//     size_t padding = (16 - (originalSize % 16)) % 16, paddedSize = originalSize + padding;
//     if (paddedSize > MAX_SIZE) {
//         printf("Padded size exceeds the maximum size of 4 GB. Adjust your shellcode or padding.\n");
//         return;
//     }
//     unsigned char paddedShellcode[paddedSize];
//     memcpy(paddedShellcode, shellcode, originalSize);
//     for (size_t i = originalSize; i < paddedSize; i++) {
//         paddedShellcode[i] = 0x00;
//     }
//     for (size_t i = 0; i < paddedSize; i++) {
//         printf("\\x%02x", paddedShellcode[i]);
//     }
// }
size_t padAndStoreShellcode(unsigned char *shellcode, size_t originalSize) {
    // Calculate padding and padded size
    size_t padding = (16 - (originalSize % 16)) % 16, paddedSize = originalSize + padding;
    if (paddedSize > MAX_SIZE) {
        printf("Padded size exceeds the maximum size of 4 GB. Adjust your shellcode or padding.\n");
        return 0;
    }
    printf("\npadded size: %zu\n", paddedSize);
    unsigned char paddedShellcode[paddedSize];
    memcpy(paddedShellcode, shellcode, originalSize);
    for (size_t i = originalSize; i < paddedSize; i++) {
        paddedShellcode[i] = 0x00;
    }
    // Convert the shellcode into bytes and store in paddedShellcode
    for (int i = 0; i < paddedSize; i++) {
        sscanf(shellcode + i * 4, "\\x%02hhx", &paddedShellcode[i]);
    }
    return paddedSize;
}

char* format_hex(unsigned char* hex, size_t length) {
    size_t buffer_size = (length * 4) + 1; // Each byte takes four characters (\xXX)
    char* formatted_hex = (char*)malloc(buffer_size * sizeof(char));
    if (formatted_hex == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(1);
    }

    for (size_t i = 0; i < length; i++) {
        snprintf(formatted_hex + (i * 4), buffer_size - (i * 4), "\\x%02x", hex[i]);
    }

    return formatted_hex;
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
    int rot = rand() % 9, dec = rand() & 0xff, ciphertext_len;
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
    printf("shellcode from file:\n");
    for (size_t i = 0; i < original_length; i++) {
        printf("\\x%02x", shellcode[i]);
    }
    sanitize_shellcode(shellcode, &original_length);
    printf("\nshellcode sanitized:\n");
    for (size_t i = 0; i < original_length; i++) {
        printf("\\x%02x", shellcode[i]);
    }
    
    for (int i = 0; i < atoi(argv[2]); i++) {
        xor_encoding(shellcode, original_length, xorkey, xorkey_length);
        not_encoding(shellcode, original_length);
        rot_encoding(shellcode, original_length, rot);
        dec_encoding(shellcode, original_length, dec);
    }
    printf("\nshellcode after encoding:\n");
    for (size_t i = 0; i < original_length; i++) {
        printf("\\x%02x", shellcode[i]);
    }
    size_t paddedSize = padAndStoreShellcode(shellcode, original_length);
    printf("\nshellcode encoded & padded:\n");
    for (size_t i = 0; i < paddedSize; i++) {
        printf("\\x%02x", shellcode[i]);
    }
    printf("\n");
    
    encrypt_aes_cbc(shellcode, paddedSize, aeskey, iv, ciphertext, &ciphertext_len);
    printf("%sSHELLCODE ENCODED/ENCRYPTED:%s\n%s[+]%s Shellcode Length: %s%zu %s~> %s%d\n", CYA, RES, BLU, GRE, RED, original_length, YEL, RED, ciphertext_len);
    printf("%sunsigned char%s shellcode[]%s = %s{ %s\"", MAG, RES, YEL, RES, RED);
    char* formatted_hex = format_hex(ciphertext, ciphertext_len);//base64_encode(format_hex(ciphertext, ciphertext_len));
    printf("%s\" %s};\n", formatted_hex, RES);
    //printf("%s", format_hex(ciphertext, ciphertext_len));
    printf("%sunsigned char%s aeskey[]%s = %s{ %s\"", MAG, RES, YEL, RES, RED);
    formatted_hex = format_hex(aeskey, EVP_MAX_KEY_LENGTH);//base64_encode(format_hex(aeskey, EVP_MAX_KEY_LENGTH));
    printf("%s\" %s};\n", formatted_hex, RES);
    //printf("%s", format_hex(aeskey, EVP_MAX_KEY_LENGTH));
    printf("%sunsigned char%s iv[]%s = %s{ %s\"", MAG, RES, YEL, RES, RED);
    formatted_hex = format_hex(iv, EVP_MAX_IV_LENGTH);//base64_encode(format_hex(iv, EVP_MAX_IV_LENGTH));
    printf("%s\" %s};\n", formatted_hex, RES);
    //printf("%s", format_hex(iv, EVP_MAX_IV_LENGTH));
    printf("%sunsigned char%s xorkey[]%s = %s{ %s\"", MAG, RES, YEL, RES, RED);
    formatted_hex = format_hex(xorkey, sizeof(xorkey));//base64_encode(format_hex(xorkey, sizeof(xorkey)));
    printf("%s\" %s};\n", formatted_hex, RES);
    //printf("%s", format_hex(xorkey, sizeof(xorkey)));
    printf("%sint%s rot%s = %s%d%s;\n", MAG, RES, YEL, RED, rot, RES);
    printf("%sint%s dec%s = %s%d%s;\n", MAG, RES, YEL, RED, dec, RES);
    printf("%sint%s iterations%s = %s%d%s;\n", MAG, RES, YEL, RED, atoi(argv[2]), RES);
    free(shellcode);
    free(aeskey);
    free(iv);
    free(ciphertext);
    return 0;
}