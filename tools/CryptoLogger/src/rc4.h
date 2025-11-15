#ifndef RC4_H
#define RC4_H

#include <stdint.h>

typedef struct {
    uint8_t S[256];
    uint8_t i, j;
} rc4_ctx;

void rc4_init(rc4_ctx *ctx, const uint8_t *key, int key_len);
void rc4_crypt(rc4_ctx *ctx, const uint8_t *in, uint8_t *out, int len);

#endif //RC4_H
