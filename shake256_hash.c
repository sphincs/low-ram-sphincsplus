/*
 * This file contains the functions that are common to all SHAKE
 * parameter sets, namely the PRF_msg, HASH_msg and PRF functions
 */

#include "internal.h"
#include "shake256_func.h"
#include "fips202.h"
#include "tune.h"
#include "tiny_sphincs.h"

#if TS_SUPPORT_SHAKE

/*
 * This computes the PRF_msg function for SHAKE parameter sets
 */
void ts_shake256_prf_msg( unsigned char *output,
	             const unsigned char *opt_rand,
		     const unsigned char *message, size_t len_message,
		     struct ts_context *sc ) {
    int n = sc->ps->n;
    const unsigned char *public_key = sc->public_key;
    SHAKE256_CTX *ctx = &sc->small_iter.shake256_simple;

    ts_shake256_inc_init(ctx);

    ts_shake256_inc_absorb(ctx, CONVERT_PUBLIC_KEY_TO_PRF(public_key, n), n);
    ts_shake256_inc_absorb(ctx, opt_rand, n);
    ts_shake256_inc_absorb(ctx, message, len_message);
    ts_shake256_inc_finalize(ctx);
    ts_shake256_inc_squeeze(output, n, ctx);
}

/*
 * This computes the HASH_msg function for SHAKE parameter sets
 */
void ts_shake256_hash_msg( unsigned char *output, size_t len_output,
		     const unsigned char *randomness,
		     const unsigned char *message, size_t len_message,
		     struct ts_context *sc ) {
    int n = sc->ps->n;
    const unsigned char *public_key = sc->public_key;
    SHAKE256_CTX *ctx = &sc->small_iter.shake256_simple;

    ts_shake256_inc_init(ctx);

    const unsigned char *pk_seed = CONVERT_PUBLIC_KEY_TO_PUB_SEED(public_key, n);
    const unsigned char *pk_root = CONVERT_PUBLIC_KEY_TO_ROOT(public_key, n);

    ts_shake256_inc_absorb(ctx, randomness, n);
    ts_shake256_inc_absorb(ctx, pk_seed, n);
    ts_shake256_inc_absorb(ctx, pk_root, n);
    ts_shake256_inc_absorb(ctx, message, len_message);

    ts_shake256_inc_finalize(ctx);

    ts_shake256_inc_squeeze(output, len_output, ctx);
}

/*
 * This computes the PRF function for SHAKE parameter sets
 */
void ts_shake256_prf( unsigned char *output,
		     struct ts_context *sc ) {
    int n = sc->ps->n;
    SHAKE256_CTX *ctx = &sc->small_iter.shake256_simple;

    ts_shake256_inc_init(ctx);
 
    ts_shake256_inc_absorb(ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(sc->public_key, n), n);
    ts_shake256_inc_absorb(ctx, sc->adr, ADR_SIZE);
    ts_shake256_inc_absorb(ctx, CONVERT_PUBLIC_KEY_TO_SEC_SEED(sc->public_key, n), n);

    ts_shake256_inc_finalize(ctx);

    ts_shake256_inc_squeeze(output, n, ctx);
}

#endif
