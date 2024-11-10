// #define AES128
// #define AES192
// #define AES256
#ifndef AES192
#ifndef AES258
#define AES128
#endif
#endif
#ifndef LENGTH
#define LENGTH 16 
#endif
// alterar este valor adiciona padding, porque adicionamos blocos de bytes
#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>
#include <time.h>
#if !defined(ALIGN16)
#if defined(__GNUC__)
#define ALIGN16 __attribute__((aligned(16)))
#else
#define ALIGN16 __declspec(align(16))
#endif
#endif
typedef struct KEY_SCHEDULE
{
    ALIGN16 unsigned char KEY[16 * 15];
    unsigned int nr;
} AES_KEY;
/*test vectors were taken from http://csrc.nist.gov/publications/nistpubs/800-
38a/sp800-38a.pdf*/

ALIGN16 uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/*****************************************************************************/
void print_m128i_with_string(char *string, __m128i data)
{
    unsigned char *pointer = (unsigned char *)&data;
    int i;
    printf("%-40s[0x", string);
    for (i = 0; i < 16; i++)
        printf("%02x", pointer[i]);
    printf("]\n");
}
void print_m128i_with_string_short(char *string, __m128i data, int length)
{
    unsigned char *pointer = (unsigned char *)&data;
    int i;
    printf("%-40s[0x", string);
    for (i = 0; i < length; i++)
        printf("%02x", pointer[i]);
    printf("]\n");
}
/*****************************************************************************/
uint8_t galois_multiply(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t counter = 8;
    uint8_t hi_bit_set;
    
    while (counter--) {
        if (b & 1) {
            p ^= a;
        }
        
        hi_bit_set = (a & 0x80);
        a <<= 1;
        
        if (hi_bit_set) {
            a ^= 0x1b;
        }
        
        b >>= 1;
    }
    
    return p;
}

uint8_t gf_mul_by_2[256];
uint8_t gf_mul_by_3[256];
uint8_t gf_mul_by_9[256];
uint8_t gf_mul_by_11[256];
uint8_t gf_mul_by_13[256];
uint8_t gf_mul_by_14[256];

// Function to initialize Galois Field multiplication tables
void initialize_galois_tables() {
    for (int x = 0; x < 256; x++) {
        gf_mul_by_2[x] = galois_multiply(x, 2);
        gf_mul_by_3[x] = galois_multiply(x, 3);
        gf_mul_by_9[x] = galois_multiply(x, 9);
        gf_mul_by_11[x] = galois_multiply(x, 11);
        gf_mul_by_13[x] = galois_multiply(x, 13);
        gf_mul_by_14[x] = galois_multiply(x, 14);
    }
}
/*****************************************************************************/
void parse_arguments(const char *arg, uint8_t *key, int len) {
    for (int i = 0; i < len; i++) {
        key[i] = (uint8_t)arg[i];
    }
}

/*****************************************************************************/
int main(int argc, char *argv[])
{
    AES_KEY key;
    AES_KEY decrypt_key;
    uint8_t *PLAINTEXT = malloc(LENGTH);
    uint8_t *CIPHERTEXT;
    uint8_t *DECRYPTEDTEXT;
    uint8_t CIPHER_KEY[LENGTH];
    int i, j;
    int key_length;
    uint8_t SHUFFLE_KEY[LENGTH];
    uint8_t PERMUTATION_SKEY[8];
    uint8_t MODIFIED_ROUND_SKEY[8];
    uint8_t permutation_indices[11][16];
    uint8_t order_indices[11];
    uint8_t saes_inverse_sbox[256];
    uint8_t saes_sbox[256];
    struct timespec start, end;

    size_t buffer_size = LENGTH;
    size_t length = 0;

    // Dynamically read from stdin
    int ch;
    while ((ch = fgetc(stdin)) != EOF) {
        if (length >= buffer_size) {
            buffer_size *= 2;
            PLAINTEXT = realloc(PLAINTEXT, buffer_size);
            if (PLAINTEXT == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                return 1;
            }
        }
        PLAINTEXT[length++] = (uint8_t)ch;
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: echo -n \"plaintext\" | %s <key> <skey>\n", argv[0]);
        return 1;
    }

    parse_arguments(argv[1], CIPHER_KEY, LENGTH);
    parse_arguments(argv[2], SHUFFLE_KEY, LENGTH);
    
#ifdef AES128
#define STR "Performing SAES128 ECB.\n"
    key_length = 128;
#endif
    CIPHERTEXT = (uint8_t *)malloc(length);
    DECRYPTEDTEXT = (uint8_t *)malloc(length);


    initialize_galois_tables();

    SAES_set_shuffle_key(SHUFFLE_KEY, key_length, &PERMUTATION_SKEY, &MODIFIED_ROUND_SKEY);
    SAES_generate_bytes_permutation_indices(permutation_indices, &PERMUTATION_SKEY);
    SAES_round_key_order_permutation(order_indices, &PERMUTATION_SKEY);
    uint8_t modified_round_number = SAES_select_modified_round_number(SHUFFLE_KEY);
    SAES_create_saes_sbox(sbox, saes_sbox, &MODIFIED_ROUND_SKEY);
    SAES_create_saes_inverse_sbox(saes_sbox, saes_inverse_sbox);

    AES_set_encrypt_key(CIPHER_KEY, key_length, &key, permutation_indices, order_indices, modified_round_number, &MODIFIED_ROUND_SKEY);
    AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key, permutation_indices, order_indices, modified_round_number, &MODIFIED_ROUND_SKEY);

    clock_gettime(CLOCK_MONOTONIC, &start);

    AES_ECB_encrypt(PLAINTEXT,
                    CIPHERTEXT,
                    length,
                    key.KEY,
                    key.nr,
                    modified_round_number,
                    &MODIFIED_ROUND_SKEY,
                    saes_sbox
                    );
    clock_gettime(CLOCK_MONOTONIC, &end);

    long seconds = end.tv_sec - start.tv_sec;
    long nanoseconds = end.tv_nsec - start.tv_nsec;
    double elapsed = seconds + nanoseconds * 1e-9;

    FILE *file = fopen("../time/NI_encrypt_times.txt", "a");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    // Write the elapsed time to the file
    fprintf(file, "%.9f\n", elapsed);

    // Close the file
    fclose(file);

    clock_gettime(CLOCK_MONOTONIC, &start);
    AES_ECB_decrypt(CIPHERTEXT,
                    DECRYPTEDTEXT,
                    length,
                    decrypt_key.KEY,
                    decrypt_key.nr,
                    modified_round_number,
                    &MODIFIED_ROUND_SKEY,
                    saes_inverse_sbox,
                    key.KEY);

    clock_gettime(CLOCK_MONOTONIC, &end);

    seconds = end.tv_sec - start.tv_sec;
    nanoseconds = end.tv_nsec - start.tv_nsec;
    elapsed = seconds + nanoseconds * 1e-9;

    file = fopen("../time/NI_decrypt_times.txt", "a");
    if (file == NULL) {
        perror("Failed to open file");
        return 1;
    }

    // Write the elapsed time to the file
    fprintf(file, "%.9f\n", elapsed);

    // Close the file
    fclose(file);                
    printf("%s\n", STR);
    printf("The Cipher Key:\n");
    print_m128i_with_string("", ((__m128i *)CIPHER_KEY)[0]);
    if (key_length > 128)
        print_m128i_with_string_short("", ((__m128i *)CIPHER_KEY)[1], (key_length / 8) - 16);
    printf("The Key Schedule:\n");
    for (i = 0; i < key.nr; i++)
        print_m128i_with_string("", ((__m128i *)key.KEY)[i]);
    printf("The PLAINTEXT:\n");
    for (i = 0; i < LENGTH / 16; i++)
        print_m128i_with_string("", ((__m128i *)PLAINTEXT)[i]);
    if (LENGTH % 16)
        print_m128i_with_string_short("", ((__m128i *)PLAINTEXT)[i], LENGTH % 16);
    printf("\n\nThe CIPHERTEXT:\n");
    for (i = 0; i < LENGTH / 16; i++)
        print_m128i_with_string("", ((__m128i *)CIPHERTEXT)[i]);
    if (LENGTH % 16)
        print_m128i_with_string_short("", ((__m128i *)CIPHERTEXT)[i], LENGTH % 16);
    for (i = 0; i < LENGTH; i++)
    {
        if (DECRYPTEDTEXT[i] != PLAINTEXT[i % (16 * 4)])
        {
            printf("The DECRYPTED TEXT isn't equal to the original PLAINTEXT!");
            printf("\n\n");
            return 1;
        }
    }
    printf("The DECRYPTED TEXT equals to the original PLAINTEXT.\n\n");

    // Output results
    printf("PLAINTEXT:\n");
    for (int i = 0; i < LENGTH; i++) {
        printf("%02x", PLAINTEXT[i]);
    }
    printf("\nCIPHERTEXT:\n");
    for (int i = 0; i < LENGTH; i++) {
        printf("%02x", CIPHERTEXT[i]);
    }

    printf("\n");
    free(PLAINTEXT);
    free(CIPHERTEXT);
    free(DECRYPTEDTEXT);
    return 0;
}