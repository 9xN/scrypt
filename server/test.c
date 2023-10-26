#include <stdio.h>
#include <string.h>

#define MAX_SIZE 4000000000 // 4 GB

void padAndFormatShellcode(const char* shellcode) {
    int shellcodeLength = strlen(shellcode) / 4; // Each \x is 4 characters
    size_t originalSize = shellcodeLength;
    
    // Calculate padding and padded size
    size_t padding = (16 - (originalSize % 16)) % 16;
    size_t paddedSize = originalSize + padding;

    if (paddedSize > MAX_SIZE) {
        printf("Padded size exceeds the maximum size of 4 GB. Adjust your shellcode or padding.\n");
        return;
    }

    unsigned char paddedShellcode[paddedSize];
    memset(paddedShellcode, 0, paddedSize);

    // Convert the shellcode into bytes and store in paddedShellcode
    for (int i = 0; i < shellcodeLength; i++) {
        sscanf(shellcode + i * 4, "\\x%02hhx", &paddedShellcode[i]);
    }

    // Print the formatted shellcode
    for (size_t i = 0; i < paddedSize; i++) {
        printf("\\x%02x", paddedShellcode[i]);
    }
}

int main() {
    const char* inputShellcode = "\\x68\\x65\\x6c\\x6c\\x6f";
    padAndFormatShellcode(inputShellcode);
    return 0;
}
