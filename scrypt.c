#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define RED "\x1b[01;31m"
#define GRE "\x1b[01;32m"
#define YEL "\x1b[01;33m"
#define BLU "\x1b[01;34m"
#define MAG "\x1b[01;35m"
#define CYA "\x1b[01;36m"
#define RES "\x1b[0m"

int main(int argc, char * argv[]) {
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
        long file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        srand((unsigned int) time(NULL));
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

        unsigned char XORKEY[sizeof(shellcode)];
        for (i = 0; i < sizeof(shellcode); i++) {
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
                        shellcode2[i] = shellcode[l];
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
                RED "%lu "
                YEL "~> "
                RED "%lu\n", file_size, (file_size) * 2);
        for (i = 0; i < (file_size) * 2; i++) {
                if (i == 0)
                        printf(
                                MAG "unsigned char"
                                RES " shellcode[]"
                                YEL " = "
                                RES "{ "
                                RED "0x%02x, "
                                RES "", shellcode4[i]);
                if (i > 0 && i < ((file_size) * 2) - 1)
                        printf(RED "0x%02x, "
                                RES "", shellcode4[i]);
                if (i == ((file_size) * 2) - 1)
                        printf(RED "0x%02x"
                                RES " };\n", shellcode4[i]);
        }

        printf(
                MAG "unsigned char"
                RES " key[]"
                YEL " = "
                RES "{ ");
        for (int g = 0; g < sizeof(XORKEY); g++) {
                if (g == sizeof(XORKEY) - 1)
                        printf(RED "0x%02x" RES " };\n", XORKEY[g]);
                else
                        printf(RED "0x%02x, ", XORKEY[g]);
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

        return 0;
}

