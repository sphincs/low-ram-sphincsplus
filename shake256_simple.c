/*
 * This file contains the function that are common to the SHAKE simple
 * parameter sets, namely the F function and the T function
 */

#include "tiny_sphincs.h"
#include "internal.h"
#include "shake256_func.h"
#include "fips202.h"
#include "tune.h"

#if TS_SUPPORT_SHAKE

/*
 * Compute the F function (which is the T function with a single input)
 */
void ts_shake256_f_simple( unsigned char *output,
	             const unsigned char *inblock,
	             struct ts_context *ctx) {
    union t_iterator *t = &ctx->small_iter; /* The small_iter is always */
	                                    /* unused when this is called */

    /* For SHAKE256, the single input T function is the same as the */
    /* multinput version */
    ts_shake256_init_t_simple( t, ctx );
    ts_shake256_next_t_simple( t, inblock, ctx );
    ts_shake256_final_t_simple(output, t, ctx );
}

/* This starts the evaluation of the T function */
/* It uses 't' to store the state of the evaluation */
void ts_shake256_init_t_simple( union t_iterator *t,
		     struct ts_context *ctx ) {
    unsigned n = ctx->ps->n;
    const unsigned char *public_key = ctx->public_key;
    SHAKE256_CTX *iter = &t->shake256_simple;

    ts_shake256_inc_init(iter);

    ts_shake256_inc_absorb(iter, CONVERT_PUBLIC_KEY_TO_PUB_SEED(public_key, n), n);
    ts_shake256_inc_absorb(iter, ctx->adr, ADR_SIZE);
}

/* We call this with each of the inputs in succession */
void ts_shake256_next_t_simple( union t_iterator *t, const unsigned char *input,
		     const struct ts_context *ctx ) {
    unsigned n = ctx->ps->n;
    SHAKE256_CTX *iter = &t->shake256_simple;
    ts_shake256_inc_absorb(iter, input, n);
}

/* And we call this after we have entered all the inputs; this sets */
/* output to T(input1, input2, ..., inputn) */
void ts_shake256_final_t_simple(unsigned char *output, union t_iterator *t,
		    const struct ts_context *ctx ) {
    unsigned n = ctx->ps->n;
    SHAKE256_CTX *iter = &t->shake256_simple;

    ts_shake256_inc_finalize(iter);

    ts_shake256_inc_squeeze(output, n, iter);
}

#endif
