#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/aes.h"
#include "../common/aes.c"

#define IV_LEN 16
#define KEY_LEN 32 // 256 bit
#define DATA_LEN 64 // Data length must be: length % 16 == 0 and less than 4GB bytes

// Function to convert the shellcode into a data array and pad it
void convertShellcode(const char* shellcode, unsigned char* data, int dataSize) {
    int shellcodeLength = strlen(shellcode) / 4; // Each \x is 4 characters

    // Initialize the data array with zeros
    memset(data, 0, dataSize);

    // Convert the shellcode into bytes
    for (int i = 0; i < shellcodeLength; i++) {
        sscanf(shellcode + i * 4, "\\x%02hhx", &data[i]);
    }
}

int main() {
    unsigned char iv[IV_LEN] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    unsigned char key[KEY_LEN] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    // Shellcode to data conversion
    char shellcode[] = "\x35\x51\x8b\xb5\xca\x5b\xa7\xa8\x24\x2b\xba\xcf\x33\x88\xac\xe7\x13\xc3\x9e\x35\xfa\x89\xff\xd3\x57\xb7\xc6\xfc\x97\x4f\xd9\xcc\xa0\x64\x81\x6a\xbf\x29\x12\xe4\x54\xcc\xb3\x87\x54\x5f\x6e\x68\x23\x0d\x9d\x1d\x96\x9c\xf1\xed\x54\xb7";
    unsigned char data[DATA_LEN];

    convertShellcode(shellcode, data, DATA_LEN);

    // Begin test
    struct AES_ctx ctx;
    AES256CBC_init_ctx_iv(&ctx, key, iv);
    AES256CBC_encrypt(&ctx, shellcode, DATA_LEN);
    printf("encrypted data:\n");
    for (int i = 0; i < DATA_LEN; i++) {
        printf("\\x%02x", (unsigned char)shellcode[i]);
    }

    // Must re-initiate after using the key and iv
    AES256CBC_init_ctx_iv(&ctx, key, iv);
    AES256CBC_decrypt(&ctx, shellcode, DATA_LEN);
    printf("\ndecrypted data:\n");
    for (int i = 0; i < DATA_LEN; i++) {
        printf("\\x%02x", (unsigned char)shellcode[i]);
    }

    return 0;
}



// /* copy paste scrypt output here */
// unsigned char shellcode[] = {/* shellcode */};
// unsigned char aeskey[] = {/* aes key */};
// unsigned char iv[] = {/* aes iv */};
// unsigned char xorkey[] = {/* xor key */};
// int rot = /* rotation value */;
// int dec = /* dec value*/;
// int iterations = /* iterations value */;
// /* ------------------ */

// void xor_encoding(unsigned char *shellcode, size_t length, unsigned char *xorkey, size_t key_length) {
//     for (size_t i = 0; i < length; i++) {
//         shellcode[i] ^= xorkey[i % key_length];
//     }
// }

// void not_encoding(unsigned char *shellcode, size_t length) {
//     for (size_t i = 0; i < length; i++) {
//         shellcode[i] = ~shellcode[i];
//     }
// }

// void rot_encoding(unsigned char *shellcode, size_t length, unsigned int rotation) {
//     for (size_t i = 0; i < length; i++) {
//         shellcode[i] = (shellcode[i] << rotation) | (shellcode[i] >> (8 - rotation));
//     }
// }

// void dec_encoding(unsigned char *shellcode, size_t length, unsigned char decrement) {
//     for (size_t i = 0; i < length; i++) {
//         shellcode[i] -= decrement;
//     }
// }

// void decrypt_aes_cbc(unsigned char *ciphertext, int ciphertext_len, unsigned char *aeskey, unsigned char *iv, unsigned char *plaintext, int *plaintext_len) {
//     struct AES_ctx ctx;
//     AES256CBC_init_ctx_iv(&ctx, aeskey, iv);
//     AES256CBC_decrypt(&ctx, ciphertext, ciphertext_len);
//     *plaintext_len = ciphertext_len;
// }

// void format_and_print(unsigned char *shellcode, size_t length) {
//     for (size_t i = 0; i < length; i++) {
//         printf("\\x%02x", shellcode[i]);
//     }
// }

// int main() {
//     print_banner();
//     int i, shellcode_len = sizeof(shellcode), decrypted_length = shellcode_len, ciphertext_len = shellcode_len - 1, aeskey_length = sizeof(aeskey) - 1, xorkey_length = sizeof(xorkey) - 1;
//     unsigned char decrypted_shellcode[shellcode_len];
//     unsigned char *ciphertext = malloc(ciphertext_len);
//     memcpy(ciphertext, shellcode, ciphertext_len);
//     decrypt_aes_cbc(ciphertext, ciphertext_len, aeskey, iv, decrypted_shellcode, &decrypted_length);
//     for (i = 0; i < iterations; i++) {
//         dec_encoding(decrypted_shellcode, decrypted_length, -dec);
//         rot_encoding(decrypted_shellcode, decrypted_length, 8 - rot);
//         not_encoding(decrypted_shellcode, decrypted_length);
//         xor_encoding(decrypted_shellcode, decrypted_length, xorkey, xorkey_length);
//     }
//     printf("SHELLCODE DECODED/DECRYPTED:%s\n%s", RES, RED);
//     format_and_print(decrypted_shellcode, decrypted_length);
//     free(ciphertext);
//     return 0;
// }
