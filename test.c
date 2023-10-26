#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}
// Function to encrypt using AES-CBC
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

// Function to encode data to Base64
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    char *buffer;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, data, input_length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *output_length = bufferPtr->length;
    buffer = (char *)malloc(*output_length);
    memcpy(buffer, bufferPtr->data, *output_length);
    OPENSSL_free(bufferPtr->data);

    return buffer;
}

// Function to decode Base64 data
unsigned char *base64_decode(const char *input_data, size_t input_length, size_t *output_length) {
    BIO *bio, *b64;
    unsigned char *buffer = (unsigned char *)malloc(input_length);
    size_t length;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf((void *)input_data, input_length);
    bio = BIO_push(b64, bio);

    *output_length = BIO_read(bio, buffer, input_length);
    BIO_free_all(bio);

    return buffer;
}

int main() {
    // Input data
    unsigned char plaintext[] = "Hello, this is a secret message!";
    unsigned char aeskey[] = "0123456789abcdef0123456789abcdef"; // 256-bit key (32 bytes)
    unsigned char iv[] = "1234567890abcdef"; // 128-bit IV (16 bytes)

    // Calculate lengths
    int plaintext_len = strlen((char *)plaintext);
    int ciphertext_len = plaintext_len + EVP_MAX_BLOCK_LENGTH;
    size_t base64_encoded_len, base64_decoded_len;

    // Encrypt the plaintext
    unsigned char ciphertext[ciphertext_len];
    encrypt_aes_cbc(plaintext, plaintext_len, aeskey, iv, ciphertext, &ciphertext_len);
    printf("Plaintext: %s\n", plaintext);
    printf("Encrypted (Hex): %.*s\n", ciphertext_len, ciphertext);
    // Print encrypted ciphertext (in Base64)
    char *base64_encoded = base64_encode(ciphertext, ciphertext_len, &base64_encoded_len);
    printf("Encrypted (Base64): %s\n", base64_encoded);
    printf("%d\n", base64_encoded_len);
    printf("%d\n", base64_decoded_len);
    // Decode Base64 data
    unsigned char *decoded_ciphertext = base64_decode(base64_encoded, base64_encoded_len, &base64_decoded_len);

    // Decrypt the ciphertext back to the original plaintext
    int decrypted_len = base64_decoded_len + EVP_MAX_BLOCK_LENGTH;
    unsigned char decrypted_text[decrypted_len];

    printf("%d\n", base64_decoded_len);
    printf("%d\n", EVP_MAX_BLOCK_LENGTH);

    // print out the length of all the variables in decrypt_aes_cbc()
    printf("AES KEY LENGTH: %d\n", strlen(aeskey));
    printf("IV LENGTH: %d\n", strlen(iv));
    printf("CIPHERTEXT LENGTH: %d\n", ciphertext_len);
    printf("DECRYPTED LENGTH: %d\n", decrypted_len);
    // Assuming decrypt_aes_cbc function is correctly implemented
    decrypt_aes_cbc(decoded_ciphertext, base64_decoded_len, aeskey, iv, decrypted_text, &decrypted_len);

    // Print decrypted plaintext
    printf("Decrypted: %.*s\n", decrypted_len, decrypted_text);
    // Free allocated memory
    free(base64_encoded);
    free(decoded_ciphertext);

    return 0;
}
