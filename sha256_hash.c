/*
 * This file contains the functions that are common to all SHA2
 * parameter sets, namely the PRF function and the function to start
 * a SHA-256 hash with the common prefix
 */

#include "sha2_func.h"
#include "sha2.h"
#include "internal.h"
#include <string.h>
#include "tune.h"
#include "tiny_sphincs.h"

#if TS_SUPPORT_SHA2

/*
 * This computes the PRF function for SHA2 parameter sets
 */
void ts_sha2_prf( unsigned char *output,
		     struct ts_context *sc ) {
    int n = sc->ps->n;
    SHA256_CTX *ctx = &sc->small_iter.sha2_L1_simple;
    ts_sha256_init_ctx( ctx, sc );

    ts_SHA256_update( ctx, sc->adr, SHA2_ADR_SIZE );
    ts_SHA256_update( ctx, CONVERT_PUBLIC_KEY_TO_SEC_SEED(sc->public_key, n), n );

    ts_SHA256_final_trunc( output, ctx, n );
}

/*
 * This initialized the SHA-256 context, and sets it up as having hashed
 * the 64 byte sequence <public seed> || 00 ||00 || ... || 00
 */
void ts_sha256_init_ctx( SHA256_CTX *ctx,
		     struct ts_context *sc ) {
#if TS_SHA2_OPTIMIZATION
    /*
     * We have that SHA-256 state precomputed, use that
     */
    ts_SHA256_restore_state_after_64( ctx, sc->prehash_sha256 );
#else
    /*
     * Initialize the context and hash that sequence manually
     */
    ts_SHA256_init( ctx );

    int n = sc->ps->n;
    ts_SHA256_update( ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(sc->public_key, n), n);

    for (int i = n; i < sha256_block_size; i++) {
        ts_SHA256_update( ctx, "\0", 1 );
    }
#endif
}

#endif
