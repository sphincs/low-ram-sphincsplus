#include "sha2_func.h"
#include "sha2.h"
#include "internal.h"
#include "endian.h"
#include <string.h>
#include "tune.h"

#if TS_SUPPORT_SHA2 && (TS_SUPPORT_L5 || TS_SUPPORT_L3)
void ts_sha2_L35_init_t_simple( union t_iterator *t,
		     struct ts_context *ctx ) {
    ts_sha512_init_ctx( &t->sha2_L35_simple, ctx );
    SHA512_update( &t->sha2_L35_simple, ctx->adr, SHA2_ADR_SIZE );
}

void ts_sha2_L35_next_t_simple( union t_iterator *t, const unsigned char *input,
		     const struct ts_context *ctx ) {
    int n = ctx->ps->n;
    SHA512_update( &t->sha2_L35_simple, input, n );
}

void ts_sha2_L35_final_t_simple(unsigned char *output, union t_iterator *t,
		    const struct ts_context *ctx ) {
    int n = ctx->ps->n;
    SHA512_final_trunc( output, &t->sha2_L35_simple, n );
}

#if TS_SHA2_OPTIMIZATION
void ts_sha2_L35_prehash( struct ts_context *sc ) {
    ts_sha2_L1_prehash( sc );

    int n = sc->ps->n;
    SHA512_CTX *ctx = &sc->small_iter.sha2_L35_simple;
    SHA512_init( ctx );

    SHA512_update( ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(sc->public_key, n), n );

    for (int i = n; i < sha512_block_size; i++) {
        SHA512_update( ctx, "\0", 1 );
    }

    SHA512_save_state( sc->prehash_sha512, ctx );
}
#endif

#endif
