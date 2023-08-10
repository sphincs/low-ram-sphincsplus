/*
 * This is the implementation of the PRF_msg and the H_msg for the
 * SHA2 L1 parameter sets.  For SHA2 L3, L5 parameter sets, these
 * functions use SHA-512, and so they're in a different file
 */

#include "sha2_func.h"
#include "sha2.h"
#include "internal.h"
#include "endian.h"
#include <string.h>
#include "tune.h"

#if TS_SUPPORT_SHA2

void ts_sha2_L1_prf_msg( unsigned char *output,
	             const unsigned char *opt_buffer,
		     const unsigned char *message, size_t len_message,
		     struct ts_context *sc ) {
    unsigned n = sc->ps->n;
    const unsigned char *public_key = sc->public_key;
    SHA256_CTX *ctx = &sc->small_iter.sha2_L1_simple;
    unsigned char block[sha256_block_size];
    unsigned char hash_output[32];  /* This holds the entire inner hash, even if */
	                            /* n < 32.  That's because we're during a */
	                            /* truncated HMAC based on SHA256, not an */
	                            /* HMAC based on a truncated SHA256 */

    /* Do the inner hash */
    ts_SHA256_init( ctx );
    for (unsigned i=0; i<n; i++) {
	block[i] = 0x36 ^ CONVERT_PUBLIC_KEY_TO_PRF(public_key, n)[i];
    }
    memset( &block[n], 0x36, sha256_block_size-n );
    ts_SHA256_update( ctx, block, sha256_block_size );
    ts_SHA256_update( ctx, opt_buffer, n );
    ts_SHA256_update( ctx, message, len_message );
    ts_SHA256_final( hash_output, ctx );

    /* Do the outer hash */
    ts_SHA256_init( ctx );
    for (unsigned i=0; i<n; i++) {
	block[i] = 0x5c ^ CONVERT_PUBLIC_KEY_TO_PRF(public_key, n)[i];
    }
    memset( &block[n], 0x5c, sha256_block_size-n );
    ts_SHA256_update( ctx, block, sha256_block_size );
    ts_SHA256_update( ctx, hash_output, 32 );
    ts_SHA256_final_trunc( output, ctx, n );
}

void ts_sha2_L1_hash_msg( unsigned char *output, size_t len_output,
		     const unsigned char *randomness,
		     const unsigned char *message, size_t len_message,
		     struct ts_context *sc ) {
    unsigned n = sc->ps->n;
    const unsigned char *public_key = sc->public_key;
    SHA256_CTX *ctx = &sc->small_iter.sha2_L1_simple;
    unsigned char msg_hash[2*TS_MAX_HASH + 32 + 4];
    ts_SHA256_init( ctx );
    ts_SHA256_update( ctx, randomness, n );
    ts_SHA256_update( ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(public_key, n), n );
    ts_SHA256_update( ctx, CONVERT_PUBLIC_KEY_TO_ROOT(public_key, n), n );
    ts_SHA256_update( ctx, message, len_message );
    ts_SHA256_final( &msg_hash[2*n], ctx );

    /* Now do the outer MGF1 */
    memcpy( &msg_hash[0], randomness, n );
    memcpy( &msg_hash[n], CONVERT_PUBLIC_KEY_TO_PUB_SEED(public_key, n), n );

    for (int i=0; len_output; i++) {
        ts_ull_to_bytes(&msg_hash[2*n+32], i, 4);
        ts_SHA256_init( ctx );
        ts_SHA256_update( ctx, msg_hash, 2*n+32+4 );

	    /* Why do we use an intermediate buffer, rather than directly */
	    /* outputing to output using ts_SHA256_final_trunc?  Because */
	    /* len_output might not be a multiple of 4 (and we're not */
	    /* actually on the critical path for stack space, so it's */
	    /* not that big of an issue) */
	unsigned char buffer[32];
	ts_SHA256_final( buffer, ctx );
	unsigned bytes;
        if (len_output >= 32) {
	    bytes = 32;
	} else {
            bytes = len_output;
	}
	memcpy( output, buffer, bytes );
	output += bytes;
	len_output -= bytes;
    }
}

#endif
