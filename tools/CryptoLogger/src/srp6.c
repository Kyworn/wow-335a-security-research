#include "srp6.h"
#include "bn.h"
#include "bn_ext.h"
#include "sha1.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

// Constantes SRP6 pour WoW 3.3.5a
const char* N_hex = "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7";
const int g_int = 7;

void srp6_calculate_session_key(
    const char* username,
    const char* password,
    const uint8_t* salt_bytes,
    const uint8_t* b_bytes,
    const uint8_t* client_a_bytes,
    uint8_t* session_key_out)
{
    struct bn n, g, k, a, A, B, u, x, S, base_val, exp_val; // Renommé 'base' et 'exp' pour éviter les conflits

    bignum_from_string(&n, (char*)N_hex, strlen(N_hex)); // Cast to char*
    bignum_from_int(&g, g_int);
    bignum_from_int(&k, 3);

    // Initialiser 'a' (clé privée client) avec 19 octets aléatoires
    uint8_t a_bytes[32]; // bn.h utilise 32 octets pour from_bytes
    srand(time(NULL));
    for(int i=0; i<19; ++i) a_bytes[i] = rand();
    for(int i=19; i<32; ++i) a_bytes[i] = 0; // Pad with zeros
    bignum_from_bytes(&a, a_bytes, sizeof(a_bytes));

    // A = g^a % n
    bignum_mod_exp(&A, &g, &a, &n);

    // u = SHA1(A | B)
    uint8_t A_bytes[32], B_bytes[32];
    bignum_to_bytes(&A, A_bytes, sizeof(A_bytes));
    bignum_from_bytes(&B, b_bytes, 32);
    bignum_to_bytes(&B, B_bytes, sizeof(B_bytes));
    
    SHA1_CTX sha_ctx;
    SHA1Init(&sha_ctx);
    SHA1Update(&sha_ctx, A_bytes, 32);
    SHA1Update(&sha_ctx, B_bytes, 32);
    uint8_t u_hash[20];
    SHA1Final(u_hash, &sha_ctx);
    bignum_from_bytes(&u, u_hash, sizeof(u_hash));

    // x = SHA1(s | SHA1(I | ":" | P))
    char user_pass_str[256];
    snprintf(user_pass_str, sizeof(user_pass_str), "%s:%s", username, password);
    for(char *p = user_pass_str; *p; ++p) *p = toupper(*p);
    
    uint8_t user_pass_hash[20];
    SHA1Init(&sha_ctx);
    SHA1Update(&sha_ctx, (unsigned char*)user_pass_str, strlen(user_pass_str));
    SHA1Final(user_pass_hash, &sha_ctx);

    uint8_t x_hash_input[32 + 20];
    memcpy(x_hash_input, salt_bytes, 32);
    memcpy(x_hash_input + 32, user_pass_hash, 20);

    uint8_t x_hash[20];
    SHA1Init(&sha_ctx);
    SHA1Update(&sha_ctx, x_hash_input, sizeof(x_hash_input));
    SHA1Final(x_hash, &sha_ctx);
    bignum_from_bytes(&x, x_hash, sizeof(x_hash));

    // S = (B - k * g^x) ^ (a + u * x) % n
    struct bn g_pow_x;
    bignum_mod_exp(&g_pow_x, &g, &x, &n); // g^x
    bignum_mul(&base_val, &k, &g_pow_x);      // k * g^x
    bignum_sub(&base_val, &B, &base_val);      // B - k*g^x
    bignum_mul(&exp_val, &u, &x);          // u*x
    bignum_add(&exp_val, &a, &exp_val);        // a + u*x
    bignum_mod_exp(&S, &base_val, &exp_val, &n);

    // Dérivation de la clé K
    uint8_t S_bytes[32];
    bignum_to_bytes(&S, S_bytes, sizeof(S_bytes));

    uint8_t even_bytes[16], odd_bytes[16];
    for(int i=0; i<16; ++i) {
        even_bytes[i] = S_bytes[i*2];
        odd_bytes[i] = S_bytes[i*2+1];
    }

    uint8_t h_even[20], h_odd[20];
    SHA1Init(&sha_ctx);
    SHA1Update(&sha_ctx, even_bytes, sizeof(even_bytes));
    SHA1Final(h_even, &sha_ctx);

    SHA1Init(&sha_ctx);
    SHA1Update(&sha_ctx, odd_bytes, sizeof(odd_bytes));
    SHA1Final(h_odd, &sha_ctx);

    for(int i=0; i<20; ++i) {
        session_key_out[i*2] = h_even[i];
        session_key_out[i*2+1] = h_odd[i];
    }
}
