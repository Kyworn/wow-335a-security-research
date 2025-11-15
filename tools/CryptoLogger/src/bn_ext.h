#ifndef BN_EXT_H
#define BN_EXT_H

#include "bn.h"
#include <stdint.h>
#include <stddef.h>

// Extensions pour tiny-bignum-c

// Charger depuis bytes (big-endian)
void bignum_from_bytes(struct bn* n, const uint8_t* bytes, size_t len);

// Exporter vers bytes (big-endian)
void bignum_to_bytes(const struct bn* n, uint8_t* bytes, size_t len);

// Exponentiation modulaire: result = base^exp mod modulus
void bignum_mod_exp(struct bn* result, const struct bn* base, const struct bn* exp, const struct bn* modulus);

#endif // BN_EXT_H
