#include <string.h>
#include "tiny_sphincs.h"
#include "internal.h"

/*
 * This generates a public/private keypair.
 * This gets hot-and-heavy with the internals of the signing logic
 */
int ts_gen_key( unsigned char *private_key,
		unsigned char *public_key,
		const struct ts_parameter_set *ps,
		int (*random_function)(unsigned char *, size_t)) {
    if (!random_function || !private_key || !ps) {
	/* We need these - the public_key parameter is optional */
	return 0;
    }
    unsigned n = ps->n;

    /* Pick a random private key */
    if (!random_function( private_key, 3*n )) {
	/* Oops, our random function claimed failure */
	return 0;
    }

    /*
     * The only part left to do is generate the root
     * To do this, we dummy up a context, and convince it to generate
     * the top level Merkle tree
     */
    struct ts_context ctx;
    memset( &ctx, 0, sizeof ctx );  /* Just in case we forget to */
                                    /* initialize something */
    ctx.ps = ps;
    unsigned char *pub;  /* Writable pointer to the public key */
    ctx.public_key = pub = CONVERT_PRIVATE_KEY_TO_PUBLIC(private_key, n);
#if TS_SHA2_OPTIMIZATION
    if (ps->compute_prehash) ps->compute_prehash( &ctx );
#endif

    ctx.buffer_offset = n;
    ctx.hypertree_level = ps->d - 1; /* We're at the top of the hypertree */
    ctx.tree_address = 0;  /* The top of the hypertree has tree address 0 */ 
    ctx.auth_path_node = 0; /* Actually, we don't care which leaf we use */
    ctx.merkle_level = 0;

    /*
     * Generate the top level Merkle tree; we perform the same logic that
     * the signing process does, using the fact that ts_merkle_path
     * keeps the root of the subtree computed so far in auth_path_buffer
     */
    ts_wots_leaf( ctx.auth_path_buffer, ctx.auth_path_node, &ctx );
    for (int i=0; i<ps->merkle_h; i++) {
        ts_merkle_path( ts_wots_leaf, &ctx, ADR_TYPE_HASHTREE,
                     ctx.x.merkle.stack );
    }

    /* The top level root is in auth_path_buffer; that's the root of the */
    /* entire Sphincs+ hypertree.  Copy it to its place in the key */
    memcpy( CONVERT_PUBLIC_KEY_TO_ROOT(pub, n),
	    ctx.auth_path_buffer, n );

    /* And if the caller asked for the public key, give it to them */
    if (public_key) {
	memcpy( public_key, pub, 2*n );
    }

    return 1;
}
