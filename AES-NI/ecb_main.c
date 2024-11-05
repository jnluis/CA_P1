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
    AES_set_encrypt_key(CIPHER_KEY, key_length, &key);
    AES_set_decrypt_key(CIPHER_KEY, key_length, &decrypt_key);

    SAES_set_shuffle_key(SHUFFLE_KEY, key_length, &PERMUTATION_SKEY, &MODIFIED_ROUND_SKEY);
    SAES_generate_bytes_permutation_indices(permutation_indices, &PERMUTATION_SKEY);
    SAES_round_key_order_permutation(order_indices, &PERMUTATION_SKEY);
    uint8_t modified_round_number = SAES_select_modified_round_number(SHUFFLE_KEY);
    printf("The modified round number is %d\n", modified_round_number);

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