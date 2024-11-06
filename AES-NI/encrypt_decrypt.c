
#include <wmmintrin.h>
#include <stdint.h>
/* Note – the length of the output buffer is assumed to be a multiple of 16 bytes */
void AES_ECB_encrypt(const unsigned char *in, // pointer to the PLAINTEXT
                     unsigned char *out,      // pointer to the CIPHERTEXT buffer
                     unsigned long length,    // text length in bytes
                     const char *key,         // pointer to the expanded key schedule
                     int number_of_rounds,    // number of AES rounds 10,12 or 14
                     int modified_round_number,
                     uint8_t *modified_round_skey)    
{
    __m128i tmp;
    int i, j;
    if (length % 16)
        length = length / 16 + 1;
    else
        length = length / 16;
    for (i = 0; i < length; i++)
    {
        tmp = _mm_loadu_si128(&((__m128i *)in)[i]);
        tmp = _mm_xor_si128(tmp, ((__m128i *)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
        {
            if (j == modified_round_number)
            {
                // XOR key with the modified round key
                for (int k = 0; k < 16; k++)
                {
                    ((__m128i *)key)[j] = _mm_xor_si128(((__m128i *)key)[j], ((__m128i *)modified_round_skey)[k % 8]);
                }
            }
            tmp = _mm_aesenc_si128(tmp, ((__m128i *)key)[j]);
            if (j == modified_round_number)
            {
                // Print the block
                print_m128i_with_string_short("Block after modified round key", tmp, 16);
            }
        }
        tmp = _mm_aesenclast_si128(tmp, ((__m128i *)key)[j]);
        _mm_storeu_si128(&((__m128i *)out)[i], tmp);
    }
}
void AES_ECB_decrypt(const unsigned char *in, // pointer to the CIPHERTEXT
                     unsigned char *out,      // pointer to the DECRYPTED TEXT buffer
                     unsigned long length,    // text length in bytes
                     const char *key,         // pointer to the expanded key schedule
                     int number_of_rounds)    // number of AES rounds 10,12 or 14
{
    __m128i tmp;
    int i, j;
    if (length % 16)
        length = length / 16 + 1;
    else
        length = length / 16;
    for (i = 0; i < length; i++)
    {
        tmp = _mm_loadu_si128(&((__m128i *)in)[i]);
        tmp = _mm_xor_si128(tmp, ((__m128i *)key)[0]);
        for (j = 1; j < number_of_rounds; j++)
        {
            tmp = _mm_aesdec_si128(tmp, ((__m128i *)key)[j]);
        }
        tmp = _mm_aesdeclast_si128(tmp, ((__m128i *)key)[j]);
        _mm_storeu_si128(&((__m128i *)out)[i], tmp);
    }
}