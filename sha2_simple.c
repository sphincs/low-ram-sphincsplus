#include "sha2_func.h"
#include "sha2.h"
#include "internal.h"
#include <string.h>

#if TS_SUPPORT_SHA2

void ts_sha2_f_simple( unsigned char *output,
	             const unsigned char *inblock,
	             struct ts_context *sc) {
    SHA256_CTX *ctx = &sc->small_iter.sha2_L1_simple;
    int n = sc->ps->n;
    ts_sha256_init_ctx( ctx, sc );

    ts_SHA256_update( ctx, sc->adr, SHA2_ADR_SIZE );
    ts_SHA256_update( ctx, inblock, n );

    ts_SHA256_final_trunc( output, ctx, n );
}

#endif
