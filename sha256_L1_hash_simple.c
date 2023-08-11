/*
 * This file contains the T function implementation for SHA2 L1 simple
 * parameter sets
 *
 * This is specific to L1 because L3, L5 SHA2 parameter sets use SHA-512
 * to perform their hashes; for those parameter sets, look in
 * sha512_L35_hash_simple.c
 *
 * Now, this is specific to T functions that take two or more inputs;
 * single input T function (also known as F) use a different function
 * that always uses SHA-256
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

#if TS_SUPPORT_SHA2

/* This starts the evaluation of the T function */
/* It uses 't' to store the state of the evaluation */
void ts_sha2_L1_init_t_simple( union t_iterator *t,
		     struct ts_context *ctx ) {
    ts_sha256_init_ctx( &t->sha2_L1_simple, ctx );

    ts_SHA256_update( &t->sha2_L1_simple, ctx->adr, SHA2_ADR_SIZE );
}

/* We call this with each of the inputs in succession */
void ts_sha2_L1_next_t_simple( union t_iterator *t, const unsigned char *input,
		     const struct ts_context *ctx ) {
    int n = ctx->ps->n;
    ts_SHA256_update( &t->sha2_L1_simple, input, n );
}

/* And we call this after we have entered all the inputs; this sets */
/* output to T(input1, input2, ..., inputn) */
void ts_sha2_L1_final_t_simple(unsigned char *output, union t_iterator *t,
		    const struct ts_context *ctx ) {
    int n = ctx->ps->n;
    ts_SHA256_final_trunc( output, &t->sha2_L1_simple, n );
}

#if TS_SHA2_OPTIMIZATION

/*
 * This precomputes the SHA-256 state after the 64 byte input
 *     <public seed> || 00 ||00 || ... || 00
 * Since this is a prefix for almost all of the hashes, precomputing
 * this once saves quite a bit of time
 */
void ts_sha2_L1_prehash( struct ts_context *sc ) {
    int n = sc->ps->n;
    SHA256_CTX *ctx = &sc->small_iter.sha2_L1_simple;
    ts_SHA256_init( ctx );

    ts_SHA256_update( ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(sc->public_key, n ), n );

    for (int i = n; i < sha256_block_size; i++) {
        ts_SHA256_update( ctx, "\0", 1 );
    }

    ts_SHA256_save_state( sc->prehash_sha256, ctx );
}
#endif

#endif
