/*
 * This file contains the T function implementation for SHA2 L3 and L5
 * simple parameter sets
 *
 * L3, L5 SHA2 parameter sets use SHA-512 to perform the T function;
 * for the L1 implementation, look in sha256_L1_hash_simple.c
 *
 * Now, this is specific to T functions that take two or more inputs;
 * single input T function (also known as F) use a different function
 * that always uses SHA-256 for all SHA2 parameter sets
 *
 * Also, were we to implement robust parameter sets, we'd have different
 * versions of these functions.  When we originally wrote this, we
 * expected that as a possibility, hence the 'simple' in the file name
 */

#include "sha2_func.h"
#include "sha2.h"
#include "internal.h"
#include "endian.h"
#include <string.h>
#include "tune.h"

#if TS_SUPPORT_SHA2 && (TS_SUPPORT_L5 || TS_SUPPORT_L3)

/* This starts the evaluation of the T function */
/* It uses 't' to store the state of the evaluation */
void ts_sha2_L35_init_t_simple( union t_iterator *t,
		     struct ts_context *ctx ) {
    ts_sha512_init_ctx( &t->sha2_L35_simple, ctx );
    ts_SHA512_update( &t->sha2_L35_simple, ctx->adr, SHA2_ADR_SIZE );
}

/* We call this with each of the inputs in succession */
void ts_sha2_L35_next_t_simple( union t_iterator *t, const unsigned char *input,
		     const struct ts_context *ctx ) {
    int n = ctx->ps->n;
    ts_SHA512_update( &t->sha2_L35_simple, input, n );
}

/* And we call this after we have entered all the inputs; this sets */
/* output to T(input1, input2, ..., inputn) */
void ts_sha2_L35_final_t_simple(unsigned char *output, union t_iterator *t,
		    const struct ts_context *ctx ) {
    int n = ctx->ps->n;
    ts_SHA512_final_trunc( output, &t->sha2_L35_simple, n );
}

#if TS_SHA2_OPTIMIZATION

/*
 * This precomputes the SHA-512 state after the 128 byte input
 *     <public seed> || 00 ||00 || ... || 00
 * as well as the corresponding SHA-256 state after 64 byte inputs.
 *
 * Since this is a prefix for almost all of the hashes, precomputing
 * this once saves quite a bit of time.  For L3, L5 SHA2 parameter
 * sets, we use both hashes, so we precompute both hash states
 */
void ts_sha2_L35_prehash( struct ts_context *sc ) {
    /* This will precompute the SHA-256 state */
    ts_sha2_L1_prehash( sc );

    /* And we have to precompute the SHA-512 state ourselves */
    int n = sc->ps->n;
    SHA512_CTX *ctx = &sc->small_iter.sha2_L35_simple;
    ts_SHA512_init( ctx );

    ts_SHA512_update( ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(sc->public_key, n), n );

    for (int i = n; i < sha512_block_size; i++) {
        ts_SHA512_update( ctx, "\0", 1 );
    }

    ts_SHA512_save_state( sc->prehash_sha512, ctx );
}
#endif

#endif
