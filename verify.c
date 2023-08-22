/*
 * This is the Sphincs+ verification logic for the tiny Sphincs
 * implementation
 */
#include <string.h>
#include "tiny_sphincs.h"
#include "internal.h"

/*
 * Why do we use a local copy of memcmp, rather than the stdlib version?
 * Well, in my machine, the stdlib version uses 1k of stack space,
 * throwing off my ram space measurements.
 * If you prefer, you can replace my_memcmp with the stdlib memcmp.  All
 * we need is something that returns 0 if the two buffers are the same,
 * nonzero if they aren't.
 */
static int my_memcmp( const unsigned char *a, const unsigned char *b,
	              unsigned n ) {
    while (n--) {
	if (*a++ != *b++) {
	    return 1;
	}
    }
    return 0;
}

/*
 * This starts the signature verification process
 */
void ts_init_verify( struct ts_context *ctx,
                   const void *message, size_t len_message,
                   const struct ts_parameter_set *ps,
                   const unsigned char *public_key ) {
    ctx->ps = ps;
    ctx->public_key = public_key;
    ctx->state = ts_verify_init;  /* We're waiting for the R in the sig */
    ctx->buffer_offset = 0;
    ctx->x.verify.message = message;
    ctx->x.verify.len_message = len_message;

#if TS_SHA2_OPTIMIZATION
    if (ps->compute_prehash) ps->compute_prehash( ctx );
#endif
}

/*
 * This will process ctx->buffer as the next entry in an authentication
 * path (within either a FORS or a Merkle tree).  typecode will be the
 * code specific to what we're processing: ADR_TYPE_FORSTREE if we're
 * processing a FORS authentication path, ADR_TYPE_HASHTREE if we're
 * processing a Merkle authentication path
 *
 * ctx->auth_path_node contains the hash from the node just below us
 */
static void next_auth_path( struct ts_context *ctx,
	                    enum hash_reason typecode ) {
    unsigned h = ctx->merkle_level; /* Height of this auth path element */
    unsigned size_h = 1 << h;

    ctx->merkle_level += 1; /* When we're done, we're on to the next level */
                            /* on the next iteration */
    ts_set_merkle_adr(ctx, ctx->auth_path_node, h, typecode);
    union t_iterator *t = &ctx->small_iter;
    ctx->ps->init_t( t, ctx );
    if ((ctx->auth_path_node & size_h) != 0) {
	/* We're at a right-hand node; buffer lies on the left */
 	ctx->ps->next_t( t, ctx->buffer, ctx );
	ctx->ps->next_t( t, ctx->auth_path_buffer, ctx );
    } else { 
	/* We're at a left-hand node; buffer lies on the right */
	ctx->ps->next_t( t, ctx->auth_path_buffer, ctx );
	ctx->ps->next_t( t, ctx->buffer, ctx );
    }
	/* Place the result back into auth_path_buffer, which is where */
	/* the next function will expect it */
    ctx->ps->final_t( ctx->auth_path_buffer, t, ctx );
}

/*
 * This sets things up to as appropriate for the start of the WOTS verify
 */
static void set_up_wots_verify_signature(struct ts_context *ctx, unsigned next_leaf) {
    /* This is exactly the set-up for the WOTS signing process... */
    ts_set_up_wots_signature(ctx, next_leaf);

    /* ... except we set the state to the verify specific state */
    ctx->state = ts_verify_wots;

    /* ... and we start hashing the WOTS heads together */
    ts_set_wots_header_adr( next_leaf, ctx );
    ctx->ps->init_t( &ctx->big_iter, ctx );

    ctx->merkle_level = 0;
}

/*
 * This processes the next M bytes of the signature to verify
 * If this notices a fatal error midway, this returns 0 - in that
 * case, the application may choose to abort the verification process
 */
int ts_update_verify( const unsigned char *sig, unsigned m,
		      struct ts_context *ctx ) {

    if (ctx->state <= ts_verify_state || ctx->state >= ts_verify_fail) {
	/* We've been handed an invalid context (or one that's been set */
	/* up for signing, or one that has already failed) - don't do */
	/* anything */
	return 0;
    }

    unsigned n = ctx->ps->n;
    for (;;) {
	unsigned buffer_offset = ctx->buffer_offset;
	unsigned remain = n - buffer_offset;
	if (remain > m) remain = m;
	memcpy( &ctx->buffer[buffer_offset], sig, remain );
	sig += remain;
	buffer_offset += remain;
	m -= remain;
	if (buffer_offset < n) {
	    ctx->buffer_offset = buffer_offset; /* We haven't filled our */
	    return 1;  /* buffer; record what we have and say we're good */
	}
	ctx->buffer_offset = 0;

	/* The next N byte of the signature are in buffer */
	/* Update the verify state machine */
	switch (ctx->state) {
	case ts_verify_init:
	    /* buffer has the 'R' value; use it to hash the message */
	    /* We reuse the fors stack space to hold the expanded */
	    /* hashed message.  The stack space is larger than we need */
            ctx->ps->hash_msg( ctx->x.fors.stack, MAX_MESSAGE_HASH,
			  ctx->buffer,
	        	  ctx->x.verify.message, ctx->x.verify.len_message,
			  ctx );
            /* Convert the hash into fors_tree leaves and position */
            /* within the hypertree */
            ts_convert_message_hash_to_hypertree_position( ctx,
			                                ctx->x.fors.stack );
            /* And after that, we'll start inputing the FORS trees */
            ctx->state = ts_verify_fors_leaf;
            ctx->fors_tree = 0;
            ctx->merkle_level = 0;
            ctx->hypertree_level = 0;

            /* And initialize the iterator that'll hash the FORS roots */
	    /* together */
            ts_set_fors_root_adr(ctx);
            ctx->ps->init_t( &ctx->big_iter, ctx );
	    break;
	case ts_verify_fors_leaf:     /* We have a FORS leaf */
	    ctx->auth_path_node = ctx->x.fors.fors_node[ctx->fors_tree];
            ctx->merkle_level = 0;
            ts_set_fors_leaf_adr(ctx, ctx->auth_path_node );
            (ctx->ps->f)( ctx->auth_path_buffer, ctx->buffer, ctx );
	    ctx->state = ts_verify_fors;
	    break;
	case ts_verify_fors:        /* We have the next hash in a */
	                            /* FORS authentication path */
	    next_auth_path( ctx, ADR_TYPE_FORSTREE );
	    if (ctx->merkle_level == ctx->ps->t) {
		 /* We hit the top of the FORS tree */
		
                 /* Add the FORS tree root to the running hash */
                 ctx->ps->next_t( &ctx->big_iter, ctx->auth_path_buffer, ctx );
		 ctx->state = ts_verify_fors_leaf;
                 ctx->fors_tree++;
		 if (ctx->fors_tree == ctx->ps->k) {
	             /* We got all the FORS root; get the final hash */
                     ctx->ps->final_t( ctx->auth_path_buffer, &ctx->big_iter, ctx );
		     ctx->fors_tree = 0;
		     set_up_wots_verify_signature(ctx, ctx->fors_keypair_addr);
		     break;
		 }
	    }
	    break;
	case ts_verify_wots: {
            int digit = ctx->x.wots.digit++;

            for (int i=ctx->x.wots.digits[digit]; i<15; i++) {
                ts_set_wots_f_adr(ctx, ctx->auth_path_node, digit, i);
                (ctx->ps->f)( ctx->buffer, ctx->buffer, ctx );
            }
            ctx->ps->next_t(&ctx->big_iter, ctx->buffer, ctx );
    
	    int d = ctx->x.wots.digit;
	    if (d != 2*ctx->ps->n + 3) break;

	    /* We've generated all the WOTS digits */
            ctx->ps->final_t(ctx->auth_path_buffer, &ctx->big_iter, ctx );
	    ctx->state = ts_verify_merkle;
	    break;
	    }
	case ts_verify_merkle:
	    next_auth_path( ctx, ADR_TYPE_HASHTREE );
	    if (ctx->merkle_level != ctx->ps->merkle_h) break;

	    /* We're at the top of the Merkle tree */
	    ctx->hypertree_level++;
	    if (ctx->hypertree_level < ctx->ps->d) {
                /* Step to the next Merkle tree level */
		unsigned next_leaf = ctx->tree_address &
			                      ((1 << ctx->ps->merkle_h)-1);
		ctx->tree_address >>= ctx->ps->merkle_h;
		set_up_wots_verify_signature(ctx, next_leaf);
	    } else {
                /* We're at the top of the hypertree - did it work? */
		if (m == 0 && 0 == my_memcmp(CONVERT_PUBLIC_KEY_TO_ROOT(
						     ctx->public_key,n),
				ctx->auth_path_buffer, n )) {
		    /* Yup, the signature checks out */
		    ctx->state = ts_verify_success;
		    return 1;
		} else {
		    /* Nope, signature didn't verify (either because */
		    /* the roots weren't the same, or there were some */
		    /* extra bytes after the signature) */
		    ctx->state = ts_verify_fail;
		    return 0;  /* Give the bad news to the caller */
		}
	    }
            break;

	default:
            ctx->state = ts_verify_fail;  /* Something awful happened; */
	    return 0;                     /* throw up our hands */
	}
    }
}

/*
 * This finishes the signature verify process.  It returns 1 if the
 * signature verifies
 */
int ts_verify( struct ts_context *ctx ) {
    /*
     * The verify process is a success if the last byte we were
     * given results in a root that matches the root in the public
     * key (state == ts_verify_success), and we weren't given any
     * bytes afterwards (buffer_offset == 0)
     */
    return ctx->state == ts_verify_success && ctx->buffer_offset == 0;
}
