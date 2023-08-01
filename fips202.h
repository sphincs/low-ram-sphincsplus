#if !defined(FIPS202_H_)
#define FIPS202_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Straight-forward API to SHAKE-256 (which is all we need)
 */

typedef struct SHAKE256_CTX {
    uint64_t s[26];
} SHAKE256_CTX;

void shake256_inc_init(SHAKE256_CTX* ctx);
void shake256_inc_absorb(SHAKE256_CTX* ctx, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(SHAKE256_CTX* ctx);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, SHAKE256_CTX* ctx);

#endif
