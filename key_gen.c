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
    ts_set_up_wots_signature(&ctx, 0);

    /*
     * Generate the top tree Merkle signature (using the space for the root
     * as the buffer - it's not being used yet).  As a side effect
     * (actually, the part we care about), this will compute the root, and
     * place it into ctx.auth_path_buffer
     */
    for (;;) {
        if (0 == ts_sign( CONVERT_PUBLIC_KEY_TO_ROOT(pub, n),
			  n, &ctx )) {
	    /* We finished computing the top level signature */
	    break;
	}
    }

    /* The root is in auth_path_buffer; copy it to its place in the key */
    memcpy( CONVERT_PUBLIC_KEY_TO_ROOT(pub, n),
	    ctx.auth_path_buffer, n );

    /* And if the caller asked for the public key, give it to them */
    if (public_key) {
	memcpy( public_key, pub, 2*n );
    }

    return 1;
}
