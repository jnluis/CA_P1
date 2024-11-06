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
ALIGN16 uint8_t AES128_KEY[] = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79,
                                     0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75};  // "Thats my Kung Fu"                                   
ALIGN16 uint8_t AES_VECTOR[] = {0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20,
                                    0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F};    // "Two One Nine Two"                                 
ALIGN16 uint8_t ECB128_EXPECTED[] = {0x29, 0xC3, 0x50, 0x5F,0x57, 0x14, 0x20, 0xF6,
                                    0x40, 0x22, 0x99, 0xB3, 0x1A, 0x02, 0xD7, 0x3A}; 
ALIGN16 uint8_t SAES_SHUFFLE_KEY[] = {0x4b, 0x75, 0x6e, 0x67, 0x20, 0x46, 0x75, 0x20,
                                    0x46, 0x69, 0x67, 0x68,0x74, 0x69, 0x6e, 0x67}; // "Kung Fu Fighting"

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
int main()
{
    AES_KEY key;
    AES_KEY decrypt_key;
    uint8_t *PLAINTEXT;
    uint8_t *CIPHERTEXT;
    uint8_t *DECRYPTEDTEXT;
    uint8_t *EXPECTED_CIPHERTEXT;
    uint8_t *CIPHER_KEY;
    int i, j;
    int key_length;
    uint8_t *SHUFFLE_KEY;
    uint8_t PERMUTATION_SKEY[8];
    uint8_t MODIFIED_ROUND_SKEY[8];
    uint8_t permutation_indices[11][16];
    uint8_t order_indices[11];
    uint8_t saes_inverse_sbox[256];
    uint8_t saes_sbox[256];
#ifdef AES128
#define STR "Performing SAES128 ECB.\n"
    CIPHER_KEY = AES128_KEY;
    EXPECTED_CIPHERTEXT = ECB128_EXPECTED;
    key_length = 128;
    SHUFFLE_KEY = SAES_SHUFFLE_KEY;
#endif
    PLAINTEXT = (uint8_t *)malloc(LENGTH);
    CIPHERTEXT = (uint8_t *)malloc(LENGTH);
    DECRYPTEDTEXT = (uint8_t *)malloc(LENGTH);
    for (i = 0; i < LENGTH / 16 / 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            _mm_storeu_si128(&((__m128i *)PLAINTEXT)[i * 4 + j],
                             ((__m128i *)AES_VECTOR)[j]);
        }
    }
    for (j = i * 4; j < LENGTH / 16; j++)
    {
        _mm_storeu_si128(&((__m128i *)PLAINTEXT)[j],
                         ((__m128i *)AES_VECTOR)[j % 4]);
    }
    if (LENGTH % 16)
    {
        _mm_storeu_si128(&((__m128i *)PLAINTEXT)[j],
                         ((__m128i *)AES_VECTOR)[j % 4]);
    }
    SAES_set_shuffle_key(SHUFFLE_KEY, key_length, &PERMUTATION_SKEY, &MODIFIED_ROUND_SKEY);
    SAES_generate_bytes_permutation_indices(permutation_indices, &PERMUTATION_SKEY);
    SAES_round_key_order_permutation(order_indices, &PERMUTATION_SKEY);
    uint8_t modified_round_number = SAES_select_modified_round_number(SHUFFLE_KEY);
    SAES_create_saes_sbox(sbox, saes_sbox, &MODIFIED_ROUND_SKEY);
    SAES_create_saes_inverse_sbox(saes_sbox, saes_inverse_sbox);

    AES_set_encrypt_key(CIPHER_KEY, key_length, &key, permutation_indices, order_indices);
    AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key,permutation_indices, order_indices);

    AES_ECB_encrypt(PLAINTEXT,
                    CIPHERTEXT,
                    LENGTH,
                    key.KEY,
                    key.nr);
    AES_ECB_decrypt(CIPHERTEXT,
                    DECRYPTEDTEXT,
                    LENGTH,
                    decrypt_key.KEY,
                    decrypt_key.nr);
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
        if (CIPHERTEXT[i] != EXPECTED_CIPHERTEXT[i % (16 * 4)])
        {
            printf("The CIPHERTEXT is not equal to the EXPECTED CIHERTEXT.\n\n");
            return 1;
        }
    }
    printf("The CIPHERTEXT equals to the EXPECTED CIHERTEXT.\n\n");
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
}