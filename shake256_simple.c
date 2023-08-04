#include "tiny_sphincs.h"
#include "internal.h"
#include "shake256_func.h"
#include "fips202.h"
#include "tune.h"

#if TS_SUPPORT_SHAKE

void ts_shake256_f_simple( unsigned char *output,
	             const unsigned char *inblock,
	             struct ts_context *ctx) {
    union t_iterator *t = &ctx->small_iter;

    /* For SHAKE256, the single input T function is the same as the */
    /* multinput version */
    ts_shake256_init_t_simple( t, ctx );
    ts_shake256_next_t_simple( t, inblock, ctx );
    ts_shake256_final_t_simple(output, t, ctx );
}

void ts_shake256_init_t_simple( union t_iterator *t,
		     struct ts_context *ctx ) {
    unsigned n = ctx->ps->n;
    const unsigned char *public_key = ctx->public_key;
    SHAKE256_CTX *iter = &t->shake256_simple;

    ts_shake256_inc_init(iter);

    ts_shake256_inc_absorb(iter, CONVERT_PUBLIC_KEY_TO_PUB_SEED(public_key, n), n);
    ts_shake256_inc_absorb(iter, ctx->adr, ADR_SIZE);
}

void ts_shake256_next_t_simple( union t_iterator *t, const unsigned char *input,
		     const struct ts_context *ctx ) {
    unsigned n = ctx->ps->n;
    SHAKE256_CTX *iter = &t->shake256_simple;
    ts_shake256_inc_absorb(iter, input, n);
}

void ts_shake256_final_t_simple(unsigned char *output, union t_iterator *t,
		    const struct ts_context *ctx ) {
    unsigned n = ctx->ps->n;
    SHAKE256_CTX *iter = &t->shake256_simple;

    ts_shake256_inc_finalize(iter);

    ts_shake256_inc_squeeze(output, n, iter);
}

#endif
