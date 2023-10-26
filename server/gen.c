#include <stdio.h>

int main() {
    // Define the variables to replace in the code
    char* shellcode = "{/* shellcode */}";
    char* aeskey = "{/* aes key */}";
    char* iv = "{/* aes iv */}";
    char* xorkey = "{/* xor key */}";
    int rot = 0;  // Set your desired values here
    int dec = 0;  // Set your desired values here
    int iterations = 0;  // Set your desired values here

    // Open a file for writing
    FILE* file = fopen("stub.c", "w");

    // Check if the file was opened successfully
    if (file == NULL) {
        printf("Error opening the file for writing.\n");
        return 1;
    }

    // Write the code template to the file with variable placeholders
    fprintf(file, "#include <openssl/err.h>\n");
    fprintf(file, "#include <openssl/evp.h>\n");
    fprintf(file, "#include <openssl/rand.h>\n");
    fprintf(file, "#include <stdio.h>\n");
    fprintf(file, "#include <stdlib.h>\n");
    fprintf(file, "#include <string.h>\n");
    fprintf(file, "#include <time.h>\n");
    fprintf(file, "\n");
    fprintf(file, "/* copy paste scrypt output here */\n");
    fprintf(file, "unsigned char shellcode[] = %s;\n", shellcode);
    fprintf(file, "unsigned char aeskey[] = %s;\n", aeskey);
    fprintf(file, "unsigned char iv[] = %s;\n", iv);
    fprintf(file, "unsigned char xorkey[] = %s;\n", xorkey);
    fprintf(file, "int rot = %d;\n", rot);
    fprintf(file, "int dec = %d;\n", dec);
    fprintf(file, "int iterations = %d;\n", iterations);
    fprintf(file, "/* ------------------ */\n");
    fprintf(file, "\n");
    fprintf(file, "const char *RED = \"\\033[01;31m\";\n");
    fprintf(file, "const char *GRE = \"\\033[01;32m\";\n");
    fprintf(file, "const char *YEL = \"\\033[01;33m\";\n");
    fprintf(file, "const char *BLU = \"\\033[01;34m\";\n");
    fprintf(file, "const char *MAG = \"\\033[01;35m\";\n");
    fprintf(file, "const char *CYA = \"\\033[01;36m\";\n");
    fprintf(file, "const char *RES = \"\\033[0m\";\n");
    fprintf(file, "\n");
    // Add the rest of the code here...

    // Close the file
    fclose(file);

    printf("The code with variable placeholders has been written to 'stub.c'.\n");

    return 0;
}
