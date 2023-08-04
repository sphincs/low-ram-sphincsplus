#if !defined(FIPS202_H_)
#define FIPS202_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Straight-forward API to SHAKE-256 (which is all we need)
 *
 * This should be obvious, but just in case; this is meant to be used
 * this way:
 *
 * SHAKE256_CTX ctx;           // Allocate the SHAKE context
 * ts_shake256_inc_init(&ctx); // Initialize it.  Forgetting to do this step
 *                             // can cause random memory overwrites (bad)
 * // Ok, now we have the text we want to hash; have the context absorb them
 * ts_shake256_inc_absorb(&ctx, text_part_1, len_text_part_1);
 * ts_shake256_inc_absorb(&ctx, text_part_2, len_text_part_2);
 * // ...
 *
 * // Ok, we've inserted the entire text
 * ts_shake256_inc_finalize(&ctx);  // Tell the context we've entered the
 *                                  // entire text
 * // And now get the SHAKE output
 * ts_shake256_inc_squeeze( output_part_1, len_output_part_1, &ctx );
 * ts_shake256_inc_squeeze( output_part_2, len_output_part_2, &ctx );
 * // and we can keep on squeezing until we've gotten all we wanted
 * 
 *
 * Remember: the absorb must come between the init and the finalize step, and
 * squeeze must come after the finalize step
 *
 */

typedef struct SHAKE256_CTX {
    uint64_t s[26];
} SHAKE256_CTX;

/* Initialize the context to an 'we haven't absorbed anything yet' state */
void ts_shake256_inc_init(SHAKE256_CTX* ctx);

/* Absorb the next inlen bytes from input into the context */
/* Note: inlen is in bytes, not in bits */
void ts_shake256_inc_absorb(SHAKE256_CTX* ctx, const uint8_t *input,
        	            size_t inlen);

/* Switch from the 'absorb' state to the 'squeeze' state */
void ts_shake256_inc_finalize(SHAKE256_CTX* ctx);

/* Extract the next outlen bytes from the shake context */ 
void ts_shake256_inc_squeeze(uint8_t *output, size_t outlen, SHAKE256_CTX* ctx);

#endif
