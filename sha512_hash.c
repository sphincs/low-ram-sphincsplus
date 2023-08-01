#include "sha2_func.h"
#include "sha2.h"
#include "internal.h"
#include "endian.h"
#include <string.h>
#include "tune.h"

#if TS_SUPPORT_SHA2 && (TS_SUPPORT_L5 || TS_SUPPORT_L3)

void ts_sha2_L35_prf_msg( unsigned char *output,
	             const unsigned char *opt_buffer,
		     const unsigned char *message, size_t len_message,
		     struct ts_context *sc ) {
    unsigned n = sc->ps->n;
    const unsigned char *public_key = sc->public_key;
    SHA512_CTX *ctx = &sc->small_iter.sha2_L35_simple;
    unsigned char block[sha512_block_size];
    unsigned char hash_output[64];

    /* Do the inner hash */
    SHA512_init( ctx );
    for (unsigned i=0; i<n; i++) {
	block[i] = 0x36 ^ CONVERT_PUBLIC_KEY_TO_PRF(public_key, n)[i];
    }
    memset( &block[n], 0x36, sha512_block_size-n );
    SHA512_update( ctx, block, sha512_block_size );
    SHA512_update( ctx, opt_buffer, n );
    SHA512_update( ctx, message, len_message );
    SHA512_final( hash_output, ctx );

    /* Do the outer hash */
    SHA512_init( ctx );
    for (unsigned i=0; i<n; i++) {
	block[i] = 0x5c ^ CONVERT_PUBLIC_KEY_TO_PRF(public_key, n)[i];
    }
    memset( &block[n], 0x5c, sha512_block_size-n );
    SHA512_update( ctx, block, sha512_block_size );
    SHA512_update( ctx, hash_output, 64 );
    SHA512_final_trunc( output, ctx, n );
}

void ts_sha2_L35_hash_msg( unsigned char *output, size_t len_output,
		     const unsigned char *randomness,
		     const unsigned char *message, size_t len_message,
		     struct ts_context *sc ) {
    unsigned n = sc->ps->n;
    const unsigned char *public_key = sc->public_key;
    SHA512_CTX *ctx = &sc->small_iter.sha2_L35_simple;
    unsigned char msg_hash[2*TS_MAX_HASH + 64 + 4];
    SHA512_init( ctx );
    SHA512_update( ctx, randomness, n );
    SHA512_update( ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(public_key, n), n );
    SHA512_update( ctx, CONVERT_PUBLIC_KEY_TO_ROOT(public_key, n), n );
    SHA512_update( ctx, message, len_message );
    SHA512_final( &msg_hash[2*n], ctx );

    /* Now do the outer MGF1 */
    memcpy( &msg_hash[0], randomness, n );
    memcpy( &msg_hash[n], CONVERT_PUBLIC_KEY_TO_PUB_SEED(public_key, n), n );

    for (int i=0; len_output; i++) {
        u32_to_bytes(&msg_hash[2*n+64], i);
        SHA512_init( ctx );
        SHA512_update( ctx, msg_hash, 2*n+64+4 );
	unsigned char buffer[64];
	SHA512_final( buffer, ctx );
	unsigned bytes;
        if (len_output >= 64) {
	    bytes = 64;
	} else {
            bytes = len_output;
	}
	memcpy( output, buffer, bytes );
	output += bytes;
	len_output -= bytes;
    }
}

void ts_sha512_init_ctx( SHA512_CTX *ctx,
		     struct ts_context *sc ) {
#if TS_SHA2_OPTIMIZATION
    SHA512_restore_state_after_128( ctx, sc->prehash_sha512 );
#else
    SHA512_init( ctx );

    int n = sc->ps->n;
    SHA512_update( ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(sc->public_key, n), n );

    for (int i = n; i < sha512_block_size; i++) {
        SHA512_update( ctx, "\0", 1 );
    }
#endif
}

#endif
