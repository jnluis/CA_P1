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
void AES_128_Key_Expansion(const unsigned char *userkey, AES_KEY *key);
int AES_set_encrypt_key(const unsigned char *userKey,
                        const int bits,
                        AES_KEY *key,
                        uint8_t *permutation_indices, 
                        uint8_t *order_indices,
                        int modified_round_number,
                        uint8_t *modified_round_skey)
{
    if (!userKey || !key)
        return -1;
    if (bits == 128)
    {
        AES_128_Key_Expansion(userKey, key);
        permute_key(key, AES_128_KEY_SCHEDULES, permutation_indices);
        shuffle_key(key, AES_128_KEY_SCHEDULES, order_indices);

        __m128i *modified_key = (__m128i *)key->KEY;
        uint8_t expanded_skey[16];
        memcpy(expanded_skey, modified_round_skey, 8);
        memcpy(expanded_skey + 8, modified_round_skey, 8);
        __m128i expanded_skey_m128 = *(__m128i *)expanded_skey;
        modified_key[modified_round_number] = _mm_xor_si128(modified_key[modified_round_number], expanded_skey_m128);

        key->nr = 10;
        return 0;
    }
    return -2;
}
int AES_set_decrypt_key(const unsigned char *userKey,
                        const int bits,
                        AES_KEY *key,
                        uint8_t *permutation_indices,
                        uint8_t *order_indices,
                        int modified_round_number,
                        uint8_t *modified_round_skey)
{
    int i, nr;
    ;
    AES_KEY temp_key;
    __m128i *Key_Schedule = (__m128i *)key->KEY;
    __m128i *Temp_Key_Schedule = (__m128i *)temp_key.KEY;
    if (!userKey || !key)
        return -1;
    if (AES_set_encrypt_key(userKey, bits, &temp_key, permutation_indices, order_indices, modified_round_number, modified_round_skey) == -2)
        return -2;
    nr = temp_key.nr;
    key->nr = nr;
    Key_Schedule[nr] = Temp_Key_Schedule[0];
    for (int i = 1; i < nr; i++) {
        if (nr - modified_round_number + 1 == nr - i) {
            Key_Schedule[nr - i] = Temp_Key_Schedule[i];
        } else {
            Key_Schedule[nr - i] = _mm_aesimc_si128(Temp_Key_Schedule[i]);
        }
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
        saes_inverse_sbox[i] = 0;
    }
    
    for (int i = 0; i < 256; i++) {
        saes_inverse_sbox[saes_sbox[i]] = i;
    }
}

void permute_key(uint8_t *exkey, uint8_t key_schedules, uint8_t *permutation_indices) {

    for (int round_idx = 0; round_idx < key_schedules; round_idx++) {
        int start = round_idx * 16;
        uint8_t permuted_round_key[16];

        // Apply permutation for the current round key
        for (int i = 0; i < 16; i++) {
            permuted_round_key[i] = exkey[start + permutation_indices[round_idx * 16 + i]];
        }

        // Copy the permuted key back into exkey
        memcpy(&exkey[start], permuted_round_key, 16);
    }

}

void shuffle_key(uint8_t *exkey, uint8_t key_schedules, const uint8_t *order_indices) {

    int idx = 0; // Track position in shuffled_exkey
    uint8_t shuffled_exkey[16 * key_schedules];

    // Loop over the specified order of round indices
    for (int i = 0; i < key_schedules; i++) {
        int start = order_indices[i] * 16;

        // Copy the 16-byte round key segment to shuffled_exkey
        memcpy(&shuffled_exkey[idx], &exkey[start], 16);
        idx += 16;
    }

    memcpy(exkey, shuffled_exkey, 16 * key_schedules);

}
