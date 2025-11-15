#ifndef SRP6_H
#define SRP6_H

#include <stdint.h>

// Calcule la clé de session RC4 de 40 octets
// La clé de sortie doit être un buffer pré-alloué de 40 octets.
void srp6_calculate_session_key(
    const char* username,
    const char* password,
    const uint8_t* salt,        // 32 bytes
    const uint8_t* server_b,    // 32 bytes
    const uint8_t* client_a,    // 32 bytes (client public key)
    uint8_t* session_key_out    // 40 bytes
);

#endif // SRP6_H
