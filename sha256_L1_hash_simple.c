#include "sha2_func.h"
#include "sha2.h"
#include "internal.h"
#include "endian.h"
#include <string.h>
#include "tune.h"

#if TS_SUPPORT_SHA2
void ts_sha2_L1_init_t_simple( union t_iterator *t,
		     struct ts_context *ctx ) {
    ts_sha256_init_ctx( &t->sha2_L1_simple, ctx );

    ts_SHA256_update( &t->sha2_L1_simple, ctx->adr, SHA2_ADR_SIZE );
}

void ts_sha2_L1_next_t_simple( union t_iterator *t, const unsigned char *input,
		     const struct ts_context *ctx ) {
    int n = ctx->ps->n;
    ts_SHA256_update( &t->sha2_L1_simple, input, n );
}

void ts_sha2_L1_final_t_simple(unsigned char *output, union t_iterator *t,
		    const struct ts_context *ctx ) {
    int n = ctx->ps->n;
    ts_SHA256_final_trunc( output, &t->sha2_L1_simple, n );
}

#if TS_SHA2_OPTIMIZATION
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
