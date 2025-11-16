#include "rc4.h"

void rc4_init(rc4_ctx *ctx, const uint8_t *key, int key_len) {
    int i, j;
    uint8_t tmp;

    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }

    for (i = 0, j = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) % 256;
        tmp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = tmp;
    }

    ctx->i = 0;
    ctx->j = 0;
}

void rc4_crypt(rc4_ctx *ctx, const uint8_t *in, uint8_t *out, int len) {
    int i;
    uint8_t tmp;

    for (i = 0; i < len; i++) {
        ctx->i = (ctx->i + 1) % 256;
        ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

        tmp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = tmp;

        out[i] = in[i] ^ ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) % 256];
    }
}
