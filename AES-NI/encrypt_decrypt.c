
#include <wmmintrin.h>
#include <stdint.h>
/* Note – the length of the output buffer is assumed to be a multiple of 16 bytes */
extern uint8_t gf_mul_by_2[256];
extern uint8_t gf_mul_by_3[256];
extern uint8_t gf_mul_by_9[256];
extern uint8_t gf_mul_by_11[256];
extern uint8_t gf_mul_by_13[256];
extern uint8_t gf_mul_by_14[256];
void mix_columns(uint8_t *block);
void mix_columns_inv(uint8_t *block);
void shift_rows(uint8_t *block);
void shift_rows_inv(uint8_t *block);
void sub_bytes(uint8_t *block, const uint8_t *sbox);
void AES_ECB_encrypt(const unsigned char *in, // pointer to the PLAINTEXT
                     unsigned char *out,      // pointer to the CIPHERTEXT buffer
                     unsigned long length,    // text length in bytes
                     const char *key,         // pointer to the expanded key schedule
                     int number_of_rounds,    // number of AES rounds 10,12 or 14
                     int modified_round_number,
                     uint8_t *modified_round_skey,
                     uint8_t *saes_sbox);

void AES_ECB_encrypt(const unsigned char *in, // pointer to the PLAINTEXT
                     unsigned char *out,      // pointer to the CIPHERTEXT buffer
                     unsigned long length,    // text length in bytes
                     const char *key,         // pointer to the expanded key schedule
                     int number_of_rounds,    // number of AES rounds 10,12 or 14
                     int modified_round_number,
                     uint8_t *modified_round_skey,
                     uint8_t *saes_sbox)    
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
                sub_bytes((uint8_t *)&tmp, saes_sbox);
                shift_rows((uint8_t *)&tmp);
                mix_columns((uint8_t *)&tmp);
                tmp = _mm_xor_si128(tmp, ((__m128i *)key)[j]);
            }
            else{
                tmp = _mm_aesenc_si128(tmp, ((__m128i *)key)[j]);
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
                     int number_of_rounds,
                     int modified_round_number,
                     uint8_t *modified_round_skey,
                     uint8_t *saes_inverse_sbox,
                     const char *old_key)
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
             if (j == number_of_rounds- modified_round_number +1 )
            {
                shift_rows_inv((uint8_t *)&tmp);
                sub_bytes((uint8_t *)&tmp, saes_inverse_sbox);
                tmp = _mm_xor_si128(tmp, ((__m128i *)key)[j]);
                mix_columns_inv((uint8_t *)&tmp);
            }
            else{
                tmp = _mm_aesdec_si128(tmp, ((__m128i *)key)[j]);
            }
        }
        tmp = _mm_aesdeclast_si128(tmp, ((__m128i *)key)[j]);
        _mm_storeu_si128(&((__m128i *)out)[i], tmp);
    }
}

void sub_bytes(uint8_t *block, const uint8_t *sbox) {
    for (int i = 0; i < 16; i++) {
        block[i] = sbox[block[i]];
    }
}

void shift_rows(uint8_t *block) {
    // Shift second row (1-byte shift left)
    uint8_t temp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp;

    // Shift third row (2-byte shift left)
    uint8_t temp1 = block[2];
    uint8_t temp2 = block[6];
    block[2] = block[10];
    block[6] = block[14];
    block[10] = temp1;
    block[14] = temp2;

    // Shift fourth row (3-byte shift left)
    temp = block[3];
    block[3] = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = temp;
}

void shift_rows_inv(uint8_t *block) {
    // Inverse shift for the second row (1-blockyte shift right)
    uint8_t temp = block[5];
    block[5] = block[1];
    block[1] = block[13];
    block[13] = block[9];
    block[9] = temp;

    // Inverse shift for the third row (2-blockyte shift right)
    temp = block[10];
    block[10] = block[2];
    block[2] = temp;
    temp = block[6];
    block[6] = block[14];
    block[14] = temp;

    // Inverse shift for the fourth row (3-blockyte shift right)
    temp = block[15];
    block[15] = block[3];
    block[3] = block[7];
    block[7] = block[11];
    block[11] = temp;

}

void mix_columns(uint8_t *block) {
    for (int col = 0; col < 16; col += 4) {
        uint8_t v0 = block[col];
        uint8_t v1 = block[col + 1];
        uint8_t v2 = block[col + 2];
        uint8_t v3 = block[col + 3];

        block[col]     = gf_mul_by_2[v0] ^ v3 ^ v2 ^ gf_mul_by_3[v1];
        block[col + 1] = gf_mul_by_2[v1] ^ v0 ^ v3 ^ gf_mul_by_3[v2];
        block[col + 2] = gf_mul_by_2[v2] ^ v1 ^ v0 ^ gf_mul_by_3[v3];
        block[col + 3] = gf_mul_by_2[v3] ^ v2 ^ v1 ^ gf_mul_by_3[v0];
    }
}

void mix_columns_inv(uint8_t *block) {
    // Loop through each column (4 bytes) in the block
    for (int col = 0; col < 16; col += 4) {
        uint8_t v0 = block[col];
        uint8_t v1 = block[col + 1];
        uint8_t v2 = block[col + 2];
        uint8_t v3 = block[col + 3];

        // Apply inverse MixColumns transformation using the precomputed tables
        block[col]     = gf_mul_by_14[v0] ^ gf_mul_by_9[v3] ^ gf_mul_by_13[v2] ^ gf_mul_by_11[v1];
        block[col + 1] = gf_mul_by_14[v1] ^ gf_mul_by_9[v0] ^ gf_mul_by_13[v3] ^ gf_mul_by_11[v2];
        block[col + 2] = gf_mul_by_14[v2] ^ gf_mul_by_9[v1] ^ gf_mul_by_13[v0] ^ gf_mul_by_11[v3];
        block[col + 3] = gf_mul_by_14[v3] ^ gf_mul_by_9[v2] ^ gf_mul_by_13[v1] ^ gf_mul_by_11[v0];
    }
}