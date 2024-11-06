/*
A function with OpenSSL interface (using AES_KEY struct), to call the other key-
length specific key expansion functions
*/
#include <wmmintrin.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <gmp.h>
#if !defined(ALIGN16)
#if defined(__GNUC__)
#define ALIGN16 __attribute__((aligned(16)))
#else
#define ALIGN16 __declspec(align(16))
#endif
#endif
#define AES_128_KEY_SCHEDULES 11
#define AES_NUMBER_OF_ROUNDS 10
typedef struct KEY_SCHEDULE
{
    ALIGN16 unsigned char KEY[16 * 15];
    unsigned int nr;
} AES_KEY;
int AES_set_encrypt_key(const unsigned char *userKey,
                        const int bits,
                        AES_KEY *key)
{
    if (!userKey || !key)
        return -1;
    if (bits == 128)
    {
        AES_128_Key_Expansion(userKey, key);
        key->nr = 10;
        return 0;
    }
    return -2;
}
int AES_set_decrypt_key(const unsigned char *userKey,
                        const int bits,
                        AES_KEY *key)
{
    int i, nr;
    ;
    AES_KEY temp_key;
    __m128i *Key_Schedule = (__m128i *)key->KEY;
    __m128i *Temp_Key_Schedule = (__m128i *)temp_key.KEY;
    if (!userKey || !key)
        return -1;
    if (AES_set_encrypt_key(userKey, bits, &temp_key) == -2)
        return -2;
    nr = temp_key.nr;
    key->nr = nr;
    Key_Schedule[nr] = Temp_Key_Schedule[0];
    Key_Schedule[nr - 1] = _mm_aesimc_si128(Temp_Key_Schedule[1]);
    Key_Schedule[nr - 2] = _mm_aesimc_si128(Temp_Key_Schedule[2]);
    Key_Schedule[nr - 3] = _mm_aesimc_si128(Temp_Key_Schedule[3]);
    Key_Schedule[nr - 4] = _mm_aesimc_si128(Temp_Key_Schedule[4]);
    Key_Schedule[nr - 5] = _mm_aesimc_si128(Temp_Key_Schedule[5]);
    Key_Schedule[nr - 6] = _mm_aesimc_si128(Temp_Key_Schedule[6]);
    Key_Schedule[nr - 7] = _mm_aesimc_si128(Temp_Key_Schedule[7]);
    Key_Schedule[nr - 8] = _mm_aesimc_si128(Temp_Key_Schedule[8]);
    Key_Schedule[nr - 9] = _mm_aesimc_si128(Temp_Key_Schedule[9]);
    if (nr > 10)
    {
        Key_Schedule[nr - 10] = _mm_aesimc_si128(Temp_Key_Schedule[10]);
        Key_Schedule[nr - 11] = _mm_aesimc_si128(Temp_Key_Schedule[11]);
    }
    if (nr > 12)
    {
        Key_Schedule[nr - 12] = _mm_aesimc_si128(Temp_Key_Schedule[12]);
        Key_Schedule[nr - 13] = _mm_aesimc_si128(Temp_Key_Schedule[13]);
    }
    Key_Schedule[0] = Temp_Key_Schedule[nr];
    return 0;
}

int SAES_set_shuffle_key(const unsigned char *userKey,
                        const int bits, uint8_t *PERMUTATION_SKEY, uint8_t *MODIFIED_ROUND_SKEY)
{
    if (!userKey)
        return -1;
    if (bits == 128)
    {
        int p_idx = 0;
        int m_idx = 0; 
        
        for (int i = 0; i < 16; i++)
        {
            if(i%2==0){
                PERMUTATION_SKEY[p_idx++] = userKey[i];
            }
            else{
                MODIFIED_ROUND_SKEY[m_idx++] = userKey[i];
            }
        }

        return 0;
    }
    return -2;
}

void SAES_generate_bytes_permutation_indices(uint8_t permutation_indices[11][16], uint8_t *permutation_key) {
    for (int round_idx = 0; round_idx < AES_128_KEY_SCHEDULES; round_idx++) {
        // Hash the permutation_key with the round index for deterministic bytes
        uint8_t uint8_hash_input[9];
        memcpy(uint8_hash_input, permutation_key, 8);
        uint8_hash_input[8] = (uint8_t)round_idx;

        unsigned char hash_input[9];
        unsigned char hash_output[SHA256_DIGEST_LENGTH];
        
        memcpy(hash_input, uint8_hash_input, 9);

        SHA256(hash_input, sizeof(hash_input), hash_output);

        // Use the hash output to generate a permutation for this round key
        uint8_t indices[16];
        for (int i = 0; i < 16; i++) {
            indices[i] = i;
        }
        for (int i = 15; i > 0; i--) {
            int swap_idx = ((uint8_t)(hash_output[i])) % (i + 1);
            uint8_t temp = indices[i];
            indices[i] = indices[swap_idx];
            indices[swap_idx] = temp;
        }

        memcpy(permutation_indices[round_idx], indices, sizeof(uint8_t) * 16);
    }
}

void SAES_round_key_order_permutation(uint8_t order_indices[11], uint8_t *permutation_key) { 

    unsigned char hash_input[8];
    memcpy(hash_input, permutation_key, 8);

    // Generate pseudo-random bytes for shuffling
    uint8_t hash_output[SHA256_DIGEST_LENGTH];
    SHA256(hash_input, sizeof(hash_input), hash_output);
    
    for (int i = 0; i < AES_128_KEY_SCHEDULES; i++) {
        order_indices[i] = i;
    }

    for (int i = AES_128_KEY_SCHEDULES - 1; i > 0; i--) {
        int swap_idx = ((uint8_t)(hash_output[i % SHA256_DIGEST_LENGTH])) % (i + 1);
        uint8_t temp = order_indices[i];
        order_indices[i] = order_indices[swap_idx];
        order_indices[swap_idx] = temp;
    }
}

uint8_t SAES_select_modified_round_number(uint8_t *skey) {
    
    unsigned char hash_input[16];
    memcpy(hash_input, skey, 16);

    // Create a hash of the secret key
    unsigned char hash_output[SHA256_DIGEST_LENGTH];

    SHA256(hash_input, sizeof(hash_input), hash_output);

    mpz_t hash_value;  // Declare a GMP integer (arbitrary precision)
    mpz_t round_number;

    mpz_init(hash_value);  // Initialize the integer
    mpz_init(round_number);

    // Convert the hexadecimal string to an integer (base 16)
    mpz_import(hash_value, SHA256_DIGEST_LENGTH, 1, sizeof(unsigned char), 0, 0, hash_output);

    // Generate a round number based on the hash value
    mpz_mod_ui(round_number, hash_value, AES_NUMBER_OF_ROUNDS - 1);
    uint8_t round_value = mpz_get_ui(round_number) + 1;

    // Clean up
    mpz_clear(hash_value);
    mpz_clear(round_number);
    return round_value;
}

void SAES_create_saes_sbox(uint8_t *sbox, uint8_t *saes_sbox, uint8_t *modified_round_skey);

void generate_shuffled_sbox(uint8_t *sbox, uint8_t *saes_sbox, uint8_t *modified_round_skey) {
    unsigned char hash_input[8];
    unsigned char hash_output[SHA256_DIGEST_LENGTH];

    memcpy(hash_input, modified_round_skey, 8);
    SHA256(hash_input, sizeof(hash_input), hash_output);
        for (int i=0;i<SHA256_DIGEST_LENGTH;i++)
    {
        printf("%02x ", hash_output[i]);
    }
    printf("\n");
    int indices[256];

    for (int i = 0; i < 256; i++) {
        indices[i] = i;
    }

    for (int i = 0; i < 256; i++) {
        int swap_idx = (i+(uint8_t)(hash_output[i % SHA256_DIGEST_LENGTH])) % 256;
        int temp = indices[i];
        indices[i] = indices[swap_idx];
        indices[swap_idx] = temp;
    }

    for (int i = 0; i < 256; i++) {
        saes_sbox[i] = sbox[indices[i]];
    }
}

void validate_and_shuffle(uint8_t *sbox, uint8_t *saes_sbox, uint8_t *modified_round_skey) {
    int changed_positions = 0;

    for (int i = 0; i < 256; i++) {
        if (saes_sbox[i] != sbox[i]) {
            changed_positions++;
        }
    }

    if (changed_positions < 128) {
        SAES_create_saes_sbox(sbox, saes_sbox, modified_round_skey);
    }
}

void SAES_create_saes_sbox(uint8_t *sbox, uint8_t *saes_sbox, uint8_t *modified_round_skey) {

    generate_shuffled_sbox(sbox, saes_sbox, modified_round_skey);
    validate_and_shuffle(sbox, saes_sbox, modified_round_skey);

}

void SAES_create_saes_inverse_sbox(uint8_t *saes_sbox, uint8_t *saes_inverse_sbox) {
    
    for (int i = 0; i < 256; i++) {
        saes_inverse_sbox[saes_sbox[i]] = i;
    }
}