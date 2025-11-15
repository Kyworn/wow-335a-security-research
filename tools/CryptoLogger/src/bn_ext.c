// Extensions pour tiny-bignum-c
// Ajoute les fonctions manquantes pour SRP6

#include "bn.h"
#include <string.h>

// Charger un bignum depuis un tableau de bytes (big-endian)
void bignum_from_bytes(struct bn* n, const uint8_t* bytes, size_t len) {
    bignum_init(n);

    // Convertir de big-endian vers little-endian array
    for (size_t i = 0; i < len && i < sizeof(n->array); i++) {
        size_t byte_idx = len - 1 - i;
        size_t word_idx = i / WORD_SIZE;
        size_t byte_in_word = i % WORD_SIZE;

        if (word_idx < BN_ARRAY_SIZE) {
            n->array[word_idx] |= ((DTYPE)bytes[byte_idx]) << (byte_in_word * 8);
        }
    }
}

// Exporter un bignum vers un tableau de bytes (big-endian)
void bignum_to_bytes(const struct bn* n, uint8_t* bytes, size_t len) {
    memset(bytes, 0, len);

    // Convertir de little-endian array vers big-endian
    for (size_t i = 0; i < len && i < sizeof(n->array); i++) {
        size_t byte_idx = len - 1 - i;
        size_t word_idx = i / WORD_SIZE;
        size_t byte_in_word = i % WORD_SIZE;

        if (word_idx < BN_ARRAY_SIZE) {
            bytes[byte_idx] = (uint8_t)((n->array[word_idx] >> (byte_in_word * 8)) & 0xFF);
        }
    }
}

// Exponentiation modulaire : result = base^exp mod modulus
// Utilise l'algorithme "square and multiply"
void bignum_mod_exp(struct bn* result, const struct bn* base, const struct bn* exp, const struct bn* modulus) {
    struct bn temp_result, temp_base, temp_exp;
    struct bn square, product;

    // Initialiser
    bignum_from_int(&temp_result, 1);  // result = 1
    bignum_assign(&temp_base, (struct bn*)base);
    bignum_assign(&temp_exp, (struct bn*)exp);

    // Algorithme square-and-multiply
    while (!bignum_is_zero(&temp_exp)) {
        // Si le bit de poids faible de exp est 1
        if (temp_exp.array[0] & 1) {
            // result = (result * base) % modulus
            bignum_mul(&temp_result, &temp_base, &product);
            bignum_mod(&product, (struct bn*)modulus, &temp_result);
        }

        // base = (base * base) % modulus
        bignum_mul(&temp_base, &temp_base, &square);
        bignum_mod(&square, (struct bn*)modulus, &temp_base);

        // exp = exp >> 1
        bignum_rshift(&temp_exp, &temp_exp, 1);
    }

    bignum_assign(result, &temp_result);
}
