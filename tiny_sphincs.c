/*
 * This is the main part of the tiny Sphincs+ (low RAM) implementation
 * It contains the signer, and much of the common logic shared between
 * the signer, key gen and the verifier
 */
#include <string.h>
#include "tiny_sphincs.h"
#include "internal.h"
#include "endian.h"

static uint64_t extract_int_from_hash( const unsigned char *hash, 
		unsigned *hash_offset, unsigned num_bits ) {
    uint64_t sum = 0;
    for (unsigned i=0; i<num_bits; i+=8) {
	sum = 256*sum + hash[ ++*hash_offset ];
    }
    return sum & ((~(uint64_t)0) >> (64 - num_bits));
}

/*
 * These are routines to set various fields in the ADR structure
 * These handle both the standard and SHA256 versions of that structure
 */
static void set_layer_adr( unsigned layer, struct ts_context *ctx ) {
    if (!TS_SUPPORT_SHAKE || ctx->ps->sha256) {
	ctx->adr[ LAYER_SHA256_OFFSET ] = layer;
    } else {
	ts_ull_to_bytes( &ctx->adr[ LAYER_OFFSET ], layer, 4 );
    }
}

static void set_tree_adr( unsigned long long tree,
	                   struct ts_context *ctx ) {
    if (!TS_SUPPORT_SHAKE || ctx->ps->sha256) {
	ts_ull_to_bytes( &ctx->adr[ TREE_SHA256_OFFSET ], tree, 8 );
    } else {
	ts_ull_to_bytes( &ctx->adr[ TREE_OFFSET ], tree, 12 );
    }
}

static void set_type_adr( unsigned type,
	                  struct ts_context *ctx ) {
    if (!TS_SUPPORT_SHAKE || ctx->ps->sha256) {
	ctx->adr[ TYPE_SHA256_OFFSET ] = type;
    } else {
	ts_ull_to_bytes( &ctx->adr[ TYPE_OFFSET ], type, 4 );
    }
}

static void set_keypair_adr( unsigned keypair,
	                   struct ts_context *ctx ) {
    if (!TS_SUPPORT_SHAKE || ctx->ps->sha256) {
	ts_ull_to_bytes( &ctx->adr[ KEYPAIR_SHA256_OFFSET ], keypair, 4 );
    } else {
	ts_ull_to_bytes( &ctx->adr[ KEYPAIR_OFFSET ], keypair, 4 );
    }
}

static void set_tree_height_adr( unsigned tree_height,
	                   struct ts_context *ctx ) {
    if (!TS_SUPPORT_SHAKE || ctx->ps->sha256) {
	ts_ull_to_bytes( &ctx->adr[ TREEHEIGHT_SHA256_OFFSET ], tree_height, 4 );
    } else {
	ts_ull_to_bytes( &ctx->adr[ TREEHEIGHT_OFFSET ], tree_height, 4 );
    }
}
#define set_chain_adr set_tree_height_adr /* Same location in adr struct */

static void set_tree_index_adr( unsigned tree_index,
	                   struct ts_context *ctx ) {
    if (!TS_SUPPORT_SHAKE || ctx->ps->sha256) {
	ts_ull_to_bytes( &ctx->adr[ TREEINDEX_SHA256_OFFSET ], tree_index, 4 );
    } else {
	ts_ull_to_bytes( &ctx->adr[ TREEINDEX_OFFSET ], tree_index, 4 );
    }
}
#define set_hash_adr set_tree_index_adr /* Same location in the adr struct */

/*
 * These are routines that set the ADR structure to be what is appropriate
 * for various hashes
 * These are initialize all fields (even the ones that are constant 0)
 */
static void set_fors_prf_adr(struct ts_context *ctx,
		   int leaf_index ) {
    set_layer_adr( 0, ctx );  /* All FORS trees are at layer 0 */
    set_tree_adr( ctx->tree_address, ctx );
    set_type_adr( ADR_TYPE_FORS_PRF, ctx );
    set_keypair_adr( ctx->fors_keypair_addr, ctx );
    set_tree_height_adr( 0, ctx ); /* FORS PRFs are done at the bottom */
                                        /* of the FORS trees */
    set_tree_index_adr( (ctx->fors_tree << ctx->ps->t) + leaf_index, ctx );
}

void ts_set_fors_leaf_adr(struct ts_context *ctx,
		                   int leaf_index ) {
    set_layer_adr( 0, ctx );  /* All FORS trees are at layer 0 */
    set_tree_adr( ctx->tree_address, ctx );
    set_type_adr( ADR_TYPE_FORSTREE, ctx );
    set_keypair_adr( ctx->fors_keypair_addr, ctx );
    set_tree_height_adr( 0, ctx ); /* FORS leaves are done at the bottom */
                                         /* of the FORS trees */
    set_tree_index_adr( (ctx->fors_tree << ctx->ps->t) + leaf_index, ctx );
}


static void set_wots_prf_adr(struct ts_context *ctx,
		   int tree_index, int leaf_index ) {
    set_layer_adr( ctx->hypertree_level, ctx );
    set_tree_adr( ctx->tree_address, ctx );
    set_type_adr( ADR_TYPE_WOTS_PRF, ctx );
    set_keypair_adr( tree_index, ctx );
    set_chain_adr( leaf_index, ctx );
    set_hash_adr( 0, ctx );  /* WOTS PRFs occur at the bottom */
}

void ts_set_wots_f_adr(struct ts_context *ctx,
		   int tree_index, int leaf_index, int hash_address ) {
    set_layer_adr( ctx->hypertree_level, ctx );
    set_tree_adr( ctx->tree_address, ctx );
    set_type_adr( ADR_TYPE_WOTS, ctx );
    set_keypair_adr( tree_index, ctx );
    set_chain_adr( leaf_index, ctx );
    set_hash_adr( hash_address, ctx );
}

void ts_set_merkle_adr(struct ts_context *ctx,
		   unsigned node, unsigned level, 
                   enum hash_reason typecode ) {
    set_layer_adr( ctx->hypertree_level, ctx );
    set_tree_adr( ctx->tree_address, ctx );
    set_type_adr( typecode, ctx );
    set_keypair_adr( ctx->fors_keypair_addr, ctx );
    set_tree_height_adr( level+1, ctx );
    set_tree_index_adr( ((ctx->fors_tree << ctx->ps->t) + node) >> (level+1), ctx );
}

void ts_set_fors_root_adr(struct ts_context *ctx) {
    set_layer_adr( 0, ctx );
    set_tree_adr( ctx->tree_address, ctx );
    set_type_adr( ADR_TYPE_FORSPK, ctx );
    set_keypair_adr( ctx->fors_keypair_addr, ctx );
    set_tree_height_adr( 0, ctx );  /* DEFAULT THESE FIELDS */
    set_tree_index_adr( 0, ctx );
}

void ts_set_wots_header_adr(unsigned merkle_leaf,
		                   struct ts_context *ctx) {
    set_layer_adr( ctx->hypertree_level, ctx );
    set_tree_adr( ctx->tree_address, ctx );
    set_type_adr( ADR_TYPE_WOTSPK, ctx );
    set_keypair_adr( merkle_leaf, ctx );
    set_tree_height_adr( 0, ctx );  /* DEFAULT THESE FIELDS */
    set_tree_index_adr( 0, ctx );
}

/*
 * Compute the PRF for a FORS leaf
 */
static void fors_prf( unsigned char *output, int leaf_index,
	              struct ts_context *ctx ) {
    set_fors_prf_adr(ctx, leaf_index );
    (ctx->ps->prf)( output, ctx );
}

/*
 * Compute the PRF for a WOTS+ chain start
 */
static void wots_prf( unsigned char *output, int tree_index,
	              int digit_index, struct ts_context *ctx) {
    set_wots_prf_adr(ctx, tree_index, digit_index );
    (ctx->ps->prf)( output, ctx );
}
		  
/*
 * Compute a FORS leaf (which is the FORS PRF followed by an F
 */
static void fors_leaf( unsigned char *output, int leaf_index,
	               struct ts_context *ctx) {
    set_fors_prf_adr(ctx, leaf_index );
    (ctx->ps->prf)( output, ctx );
    set_type_adr( ADR_TYPE_FORSTREE, ctx );  /* The adr structure */
                         /* is identical except for the type field */
    (ctx->ps->f)( output, output, ctx );
}

/*
 * Generate the next entry in the authentication path
 * It places its output into ctx->buffer
 *
 * Here is now it work: to generate the next authentication path entry
 * (which is the tree node which is the sibling to the node on the path
 * to the current leaf), we evaluate the entire subtree below that tree
 * node.
 * In addition, we also maintain the value of the node on the path to the
 * current leaf; that node is in auth_path_buffer; once we have the
 * sibling node, we can then update it to the parent node value.  At the
 * end of generating the entire authentication path, this auth_path_buffer
 * will be the value of the root.
 *
 * This is used for both FORS and Merkle trees (distinguished by the
 * typecode parameter)
 */
static void merkle_path( void (*gen_leaf)(
			        unsigned char *output, int leaf_index,
			       	struct ts_context *ctx),
	                 struct ts_context *ctx,
	                 enum hash_reason typecode,
			 unsigned char *stack) {
    unsigned n = ctx->ps->n;
    unsigned h = ctx->merkle_level; /* Height of the subtree we're */
                            /* generating */
    ctx->merkle_level += 1; /* When we're done, we're on to the next */
                            /* level on the next iteration */
    unsigned size_h = 1 << h;
    unsigned node = ctx->auth_path_node ^ size_h;
    node &= ~(size_h - 1);

    /* Step through every leaf in the subtree we're evaluating */
    for (unsigned i = 0; i<size_h; i++) {
	/* Generate that leaf */
	gen_leaf( ctx->buffer, node+i, ctx );

	/* And combine it with nodes we have stored in the stack */
	unsigned k = 0;
        for (unsigned nod = i; nod & 1; nod >>= 1, k++) {
	    union t_iterator *t = &ctx->small_iter;
            ts_set_merkle_adr(ctx, node+i, k, typecode);
	    ctx->ps->init_t( t, ctx );
	    ctx->ps->next_t( t, &stack[k*n], ctx );
	    ctx->ps->next_t( t, ctx->buffer, ctx );
	    ctx->ps->final_t( ctx->buffer, t, ctx );
	}

	/* If we're not at the top of the tree, place the intermedate */
	/* node back onto the stack */
	if (k < h) {
	    memcpy( &stack[k*n], ctx->buffer, n );
	}
    }

    /* ctx->buffer now contains the root of the subtree, which is the */
    /* authentication path element we were asked to generate */
    ctx->buffer_offset = 0;

    /* And update the auth_path buffer */
    {
        ts_set_merkle_adr(ctx, node, h, typecode);
	union t_iterator *t = &ctx->small_iter;
	ctx->ps->init_t( t, ctx );
	if ((ctx->auth_path_node & size_h) != 0) {
 	    ctx->ps->next_t( t, ctx->buffer, ctx );
	    ctx->ps->next_t( t, ctx->auth_path_buffer, ctx );
	} else { 
	    ctx->ps->next_t( t, ctx->auth_path_buffer, ctx );
	    ctx->ps->next_t( t, ctx->buffer, ctx );
	}
	ctx->ps->final_t( ctx->auth_path_buffer, t, ctx );
    }
}

/*
 * Given a H_msg output, convert it into the Hypertree leaf and
 * FORS nodes that correspond to it
 */
void ts_convert_message_hash_to_hypertree_position(
	                       struct ts_context *ctx,
			       unsigned char *message_hash ) {
    const struct ts_parameter_set *ps = ctx->ps;
    unsigned hash_offset = 0;
    unsigned bit_so_far = 0;

    for (int k=0; k<ps->k; k++) {
        unsigned this_index = 0;
	for (int t=0; t<ps->t; t++) {
	    if (bit_so_far == 8) {
		hash_offset++;
		bit_so_far = 0;
	    }
	    unsigned bit = message_hash[hash_offset];
#if 0
	    /* The ordering that the original reference code did */
	    message_hash[hash_offset] = bit>>1;
	    bit &= 1;
	    bit_so_far++;

	    this_index |= (bit << t);
#else
	    /* The ordering that NIST uses */
            message_hash[hash_offset] = bit<<1;
	    bit >>= 7;
	    bit_so_far++;

	    this_index = 2*this_index + (bit&1);
#endif
	}
	ctx->x.fors.fors_node[k] = this_index;
    }

    /* Now extract the bottom level Merkle tree */
    ctx->tree_address = extract_int_from_hash( message_hash,
		              &hash_offset, ps->h - ps->merkle_h );
    ctx->fors_keypair_addr = extract_int_from_hash( message_hash,
		              &hash_offset, ps->merkle_h );
}

/*
 * Start the signing process; initialize the ctx structure, and
 * perform the initial messag hash.  Also set the initial signature output
 * to be the 'R' value, and set things up for the computation of the
 * FORS trees
 */
void ts_init_sign( struct ts_context *ctx,
                   const void *message, size_t len_message,
                   const struct ts_parameter_set *ps,
                   const unsigned char *private_key,
	           int (*random_function)(unsigned char *, size_t) ) {
    unsigned n = ps->n;

    ctx->ps = ps;
    ctx->public_key = CONVERT_PRIVATE_KEY_TO_PUBLIC( private_key, n );

#if TS_SHA2_OPTIMIZATION
    if (ps->compute_prehash) ps->compute_prehash( ctx );
#endif

    /* Step 1: generate the randomness */
    unsigned char *randomness = ctx->buffer;  /* We'll place R right into */
                               /* right into the output buffer */
                               /* It is the initial part of the signature */
    {
        unsigned char opt_buffer[TS_MAX_HASH];
        if (!random_function || !random_function( opt_buffer, n )) {
            memcpy( opt_buffer,
		    CONVERT_PUBLIC_KEY_TO_PUB_SEED( ctx->public_key, n ),
		    n);
        }

        ps->prf_msg( randomness, opt_buffer, message, len_message, ctx );
    }

    /* Step 2: hash the message */
    unsigned char message_hash[MAX_MESSAGE_HASH];
    ps->hash_msg( message_hash, sizeof message_hash, randomness,
		     message, len_message, ctx );

    /* Step 3: convert the hash into fors_tree leaves and position */
    /* within the hypertree */
    ts_convert_message_hash_to_hypertree_position( ctx, message_hash );

    /* The very first output we generate is the randomness value */
    /* (which we've already placed into ctx->buffer) */
    ctx->buffer_offset = 0;

    /* And after that, we'll start outputing the FORS trees */
    ctx->state = ts_fors_leaf;
    ctx->fors_tree = 0;
    ctx->merkle_level = 0;
    ctx->hypertree_level = 0;

    /* And initialize the iterator that'll hash the FORS roots together */
    ts_set_fors_root_adr(ctx);
    ps->init_t( &ctx->big_iter, ctx );
}

/*
 * Given a hash, convert it into the series of WOTS digits
 */
static void compute_wots_digits( unsigned char *digits,
	                         const unsigned char *hash, int n ) {
    unsigned sum = 2*15*n;
    for (int i=0; i<n; i++) {
	unsigned char byte = *hash++;
	unsigned d;
	*digits++ = d = byte >> 4;
	sum -= d;
	*digits++ = d = byte & 0xf;
	sum -= d;
    }
    *digits++ = (sum >> 8) & 0xf;
    *digits++ = (sum >> 4) & 0xf;
    *digits   = (sum     ) & 0xf;
}

/*
 * Set the context to be reading to generate a WOTS signature
 * The hash from the structure below us (be it FORS or a child Merkle tree)
 * is in auth_path_buffer
 * This is used by the signer, key gen and the verifier
 */
void ts_set_up_wots_signature(struct ts_context *ctx, unsigned next_leaf) {
    ctx->state = ts_wots;
    ctx->x.wots.digit = 0;
        /* Compute the value of the leaf node.  We need to do that */
        /* for the incremental computation that'll result in the root */
    compute_wots_digits( ctx->x.wots.digits, ctx->auth_path_buffer,
		         ctx->ps->n );
    ctx->auth_path_node = next_leaf;
    ctx->fors_keypair_addr = 0;
}

/*
 * Generate the next hash in the current WOTS+ signature
 */
static void generate_next_wots_hash(struct ts_context *ctx) {
    int digit = ctx->x.wots.digit++;

    wots_prf( ctx->buffer, ctx->auth_path_node, digit, ctx );
    for (int i=0; i<ctx->x.wots.digits[digit]; i++) {
        ts_set_wots_f_adr(ctx, ctx->auth_path_node, digit, i);
        (ctx->ps->f)( ctx->buffer, ctx->buffer, ctx );
    }
    ctx->buffer_offset = 0;
}

/*
 * Compute a leaf of a Merkle tree (which is a WOTS public key)
 */
static void wots_leaf( unsigned char *output, int leaf_index,
	               struct ts_context *ctx ) {
    ts_set_wots_header_adr( leaf_index, ctx );
    ctx->ps->init_t( &ctx->big_iter, ctx );

    for (int d = 0; d < 2*ctx->ps->n + 3; d++) {
	unsigned char *buffer = ctx->x.merkle.buffer;
        wots_prf( buffer, leaf_index, d, ctx );
        for (int i=0; i<15; i++) {
            ts_set_wots_f_adr(ctx, leaf_index, d, i);
            (ctx->ps->f)( buffer, buffer, ctx );
        }
        ctx->ps->next_t(&ctx->big_iter, buffer, ctx );
    }
    ctx->ps->final_t(output, &ctx->big_iter, ctx );
}

/*
 * This generates the next M bytes of the signature.  It turns the
 * number of bytes actually generated.  It'll be the full N until we
 * hit the end of the signature
 */
unsigned ts_sign( unsigned char *dest, unsigned m,
                  struct ts_context *ctx ) {
    unsigned orig_m = m;
    unsigned n = ctx->ps->n;

    if (ctx->state <= ts_sign_state || ctx->state >= ts_verify_state) {
	/* We've been handed an invalid context (or one that's been set */
	/* up for verify) - don't do anything */
	return 0;
    }

    while (m) {
	/* If we have bytes left from the previous hash, given those to */
	/* the caller */
	unsigned remain = n - ctx->buffer_offset;
	if (remain > 0) {
	    if (remain > m) remain = m;
	    memcpy( dest, &ctx->buffer[ctx->buffer_offset], remain );
	    dest += remain;
	    ctx->buffer_offset += remain;
	    m -= remain;
	    continue;
	}

	/* We'll need more bytes; select where to go based on where we */
	/* are in the signature */
	switch (ctx->state) {
        case ts_fors_leaf: {   /* The next value is a FORS leaf */
	    unsigned node = ctx->x.fors.fors_node[ctx->fors_tree];
	    ctx->auth_path_node = node;
            fors_prf( ctx->buffer, node, ctx );
	    ctx->buffer_offset = 0;
	    ctx->merkle_level = 0;
	    ctx->state = ts_fors;

	    /* Kick off the process that generates the FORS auth path */
	    fors_leaf( ctx->auth_path_buffer, node, ctx );
	    continue;
	    }
	case ts_fors: {
            /* Generate the next node in the FORS Merkle path */
	    merkle_path( fors_leaf, ctx, ADR_TYPE_FORSTREE,
			 ctx->x.fors.stack );
	    if (ctx->merkle_level == ctx->ps->t) {
		 /* We hit the top of the FORS tree */
		
                 /* Add the FORS tree root to the running hash */
                 ctx->ps->next_t( &ctx->big_iter, ctx->auth_path_buffer,
			          ctx );
		 ctx->state = ts_fors_leaf;
                 ctx->fors_tree++;
		 if (ctx->fors_tree == ctx->ps->k) {
	             /* We got all the FORS root; get the final hash */
                     ctx->ps->final_t( ctx->auth_path_buffer,
				       &ctx->big_iter, ctx );
		     ctx->fors_tree = 0;
		     ts_set_up_wots_signature(ctx, ctx->fors_keypair_addr);
		 }
	    }
	    continue;
        }
	case ts_wots: {  /* The next value is from a WOTS+ signature */
            generate_next_wots_hash(ctx);
	    int d = ctx->x.wots.digit;
	    if (d == 2*ctx->ps->n + 3) {
		/* We've generated all the WOTS digits */
                ctx->state = ts_merkle;
                ctx->merkle_level = 0;
	        wots_leaf( ctx->auth_path_buffer, ctx->auth_path_node,
			   ctx );
	    }
	    continue;
	}
	case ts_merkle: {  /* The next value is from a Merkle signature */
            /* Generate the next node in the Merkle path */
	    merkle_path( wots_leaf, ctx, ADR_TYPE_HASHTREE,
			 ctx->x.merkle.stack );
	    if (ctx->merkle_level == ctx->ps->merkle_h) {
		 /* We hit the top of the Merkle tree */
		 ctx->hypertree_level++;
		 if (ctx->hypertree_level == ctx->ps->d) {
                     /* We're at the top of the hypertree - all done */
                     ctx->state = ts_done;
		     continue;
		 }
		 /* Step upwards to the parent Merkle tree */

		 ctx->auth_path_node = ctx->tree_address &
			                      ((1 << ctx->ps->merkle_h)-1);
		 ctx->tree_address >>= ctx->ps->merkle_h;
		 ts_set_up_wots_signature(ctx, ctx->auth_path_node);
	    }
	    continue;
	}
	case ts_done: default:  /* We hit the end of the signature */
	    break;
	}
	break;   /* No more bytes to generate */
    }

    return orig_m - m;
}
