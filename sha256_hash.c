#include "sha2_func.h"
#include "sha2.h"
#include "internal.h"
#include <string.h>
#include "tune.h"
#include "tiny_sphincs.h"

#if TS_SUPPORT_SHA2

void ts_sha2_prf( unsigned char *output,
		     struct ts_context *sc ) {
    int n = sc->ps->n;
    SHA256_CTX *ctx = &sc->small_iter.sha2_L1_simple;
    ts_sha256_init_ctx( ctx, sc );

    SHA256_update( ctx, sc->adr, SHA2_ADR_SIZE );
    SHA256_update( ctx, CONVERT_PUBLIC_KEY_TO_SEC_SEED(sc->public_key, n), n );

    SHA256_final_trunc( output, ctx, n );
}

void ts_sha256_init_ctx( SHA256_CTX *ctx,
		     struct ts_context *sc ) {
#if TS_SHA2_OPTIMIZATION
    SHA256_restore_state_after_64( ctx, sc->prehash_sha256 );
#else
    SHA256_init( ctx );

    int n = sc->ps->n;
    SHA256_update( ctx, CONVERT_PUBLIC_KEY_TO_PUB_SEED(sc->public_key, n), n);

    for (int i = n; i < sha256_block_size; i++) {
        SHA256_update( ctx, "\0", 1 );
    }
#endif
}

#endif
