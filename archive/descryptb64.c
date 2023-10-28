#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
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

char* base64_decode(char* cipher) {
    const char base64_map[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

    char counts = 0;
    char buffer[4];
    char* plain = malloc(strlen(cipher) * 3 / 4);
    int i = 0, p = 0;

    for(i = 0; cipher[i] != '\0'; i++) {
        char k;
        for(k = 0 ; k < 64 && base64_map[k] != cipher[i]; k++);
        buffer[counts++] = k;
        if(counts == 4) {
            plain[p++] = (buffer[0] << 2) + (buffer[1] >> 4);
            if(buffer[2] != 64)
                plain[p++] = (buffer[1] << 4) + (buffer[2] >> 2);
            if(buffer[3] != 64)
                plain[p++] = (buffer[2] << 6) + buffer[3];
            counts = 0;
        }
    }

    plain[p] = '\0';    /* string padding character */
    return plain;
}

unsigned char* base64_to_shellcode(char* cipher, size_t* original_length) {
    char* plain = base64_decode(cipher);
    size_t i = 0;
    char hexByte[3];
    unsigned char* shellcode = (unsigned char*)malloc(strlen(plain) / 2);
    
    for (i = 0; plain[i] != '\0'; i += 2) {
        hexByte[0] = plain[i];
        hexByte[1] = plain[i + 1];
        hexByte[2] = '\0';
        unsigned char byte = (unsigned char)strtol(hexByte, NULL, 16);
        if (byte != '\0') {
            shellcode[i / 2] = byte;
        }
    }

    *original_length = i / 2;
    free(plain); // Free the memory allocated by base64_decode
    return shellcode;
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

int main() {
    print_banner();
    size_t shellcode_length = 0;
    size_t aeskey_length = 0;
    size_t iv_length = 0;
    size_t xorkey_length = 0;

    unsigned char* decoded_shellcode = base64_to_shellcode(shellcode, &shellcode_length);
    unsigned char* decoded_aeskey = base64_to_shellcode(aeskey, &aeskey_length);
    unsigned char* decoded_iv = base64_to_shellcode(iv, &iv_length);
    unsigned char* decoded_xorkey = base64_to_shellcode(xorkey, &xorkey_length);

    int shellcode_len = shellcode_length;
    int decrypted_length = shellcode_len;
    int ciphertext_len = shellcode_len - 1;
    int aeskey_len = aeskey_length * 2;
    int xorkey_len = xorkey_length;

    unsigned char decrypted_shellcode[shellcode_len];
    unsigned char* ciphertext = malloc(ciphertext_len);
    memcpy(ciphertext, decoded_shellcode, ciphertext_len);

    printf("%s\n", format_hex(decoded_shellcode, shellcode_len));

    // Print out the lengths of the keys
    printf("AES KEY LENGTH: %d\n", aeskey_len);
    printf("IV LENGTH: %d\n", iv_length);
    printf("XOR KEY LENGTH: %d\n", xorkey_len);
    printf("SHELLCODE LENGTH: %d\n", shellcode_len);
    printf("CIPHERTEXT LENGTH: %d\n", ciphertext_len);
    printf("DECRYPTED LENGTH: %d\n", decrypted_length);

    decrypt_aes_cbc(ciphertext, ciphertext_len, decoded_aeskey, decoded_iv, decrypted_shellcode, &decrypted_length);

    xor_encoding(decrypted_shellcode, decrypted_length, decoded_xorkey, xorkey_len);

    for (int i = 0; i < iterations; i++) {
        dec_encoding(decrypted_shellcode, decrypted_length, -dec);
        rot_encoding(decrypted_shellcode, decrypted_length, 8 - rot);
        not_encoding(decrypted_shellcode, decrypted_length);
        xor_encoding(decrypted_shellcode, decrypted_length, decoded_xorkey, xorkey_len);
    }

    printf("SHELLCODE DECODED/DECRYPTED:%s\n%s", RES, RED);
    // Assuming format_hex function is correctly implemented
    format_hex(decrypted_shellcode, decrypted_length);

    free(ciphertext);
    free(decoded_shellcode); // Free the dynamically allocated memory for decoded data.
    free(decoded_aeskey);
    free(decoded_iv);
    free(decoded_xorkey);

    return 0;
}
