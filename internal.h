#if !defined( INTERNAL_H_ )
#define INTERNAL_H_

/*
 * These are definitions internal to the Tiny Sphincs implementation that we
 * don't need to include in the external API
 */

#include <stddef.h>
#include "tune.h"

struct ts_context;
union t_iterator;

/*
 * This defines a Sphincs+ parameter set
 */
struct ts_parameter_set {
    unsigned char n;   /* Size of the hash */
    unsigned char k;   /* # of FORS trees */
    unsigned char t;   /* Height of each FORS tree */
    unsigned char h;   /* Hypertree height */
    unsigned char d;   /* # of levels of Merkle trees */
    unsigned char merkle_h; /* Height of each Merkle tree = h/d */
    unsigned char sha256; /* Set if this is a SHA256 parameter set */

	/* The parameter-set specific functions */
	/* All these functions assume that the adr structure within the */
	/* ts_context structure has been set up */
    void (*prf_msg)( unsigned char *output, const unsigned char *opt_buffer,
		     const unsigned char *message, size_t len_message,
	             struct ts_context *ctx);
    void (*hash_msg)( unsigned char *output, size_t len_output,
		     const unsigned char *randomness,
		     const unsigned char *message, size_t len_message,
	             struct ts_context *ctx);
    void (*prf)( unsigned char *output, struct ts_context *ctx);
    void (*f)( unsigned char *output,
	             const unsigned char *inblock,
	             struct ts_context *ctx);

	/* These three functions are used to compute the H and T function */
	/* for more than one input block (for a single input T function, we */
	/* use the f function above).  First, we call init_t, then we call */
	/* next_t for each input block (in order), and then we call final_t */
	/* to get the result */
    void (*init_t)( union t_iterator *t, struct ts_context *ctx );
    void (*next_t)( union t_iterator *t, const unsigned char *input,
		    const struct ts_context *ctx );
    void (*final_t)( unsigned char *output, union t_iterator *t,
		    const struct ts_context *ctx );

    	/* This computes the initial hash of the public seed, done when we */
    	/* are first given the public key.  It is NULL if we don't need to */
        /* do this */
    void (*compute_prehash)( struct ts_context *ctx );
};

/*
 * This is how to convert various things related to keys
 * The pointer we store within the ts_context is actually a pointer to the
 * public key; if the key is actually a private one, the
 * CONVERT_PUBLIC_KEY_TO_SEC_SEED, CONVERT_PUBLIC_KEY_TO_PRF macros will still
 * fetch those values
 *
 * We do this so that the verify routine (which has only the public key,
 * and never needs to refer to anything private) can use the same routines
 */
#define CONVERT_PRIVATE_KEY_TO_PUBLIC(pk, n)   (pk + 2*n)
#define CONVERT_PUBLIC_KEY_TO_SEC_SEED(pk, n)  (pk - 2*n)
#define CONVERT_PUBLIC_KEY_TO_PRF(pk, n)       (pk - n)
#define CONVERT_PUBLIC_KEY_TO_PUB_SEED(pk, n)  (pk)
#define CONVERT_PUBLIC_KEY_TO_ROOT(pk, n)      (pk + n)

/* The type field we place into the ADR structure, based on what */
/* hash we are computing */
enum hash_reason {
    ADR_TYPE_WOTS = 0,     /* We're hashing as a part of a WOTS+ chain */
    ADR_TYPE_WOTSPK = 1,   /* We're hashing all the WOTS+ chain tops */
    ADR_TYPE_HASHTREE = 2, /* We're hashing within a Merkle tree */
    ADR_TYPE_FORSTREE = 3, /* We're hashing within a FORS tree */
    ADR_TYPE_FORSPK = 4,   /* We're generating a private FORS value */
    ADR_TYPE_WOTS_PRF = 5, /* We're evaluating PRF for WOTS+ */
    ADR_TYPE_FORS_PRF = 6, /* We're evaluation PRF for FORS */
};

#define MAX_MESSAGE_HASH 49 /* Maximum number of bytes we need from */
                            /* hash_msg.  There's no strong need to tune */
			    /* this to the parameter set */
#define SHA2_ADR_SIZE    22 /* SHA2 uses a compressed format */

/* The offsets of various fields within the ADR structure (both for */
/* standard and the compressed SHA256 version */
#define LAYER_OFFSET             0
#define LAYER_SHA256_OFFSET      0
#define TREE_OFFSET              4
#define TREE_SHA256_OFFSET       1
#define TYPE_OFFSET             16
#define TYPE_SHA256_OFFSET       9
#define KEYPAIR_OFFSET          20
#define KEYPAIR_SHA256_OFFSET   10
#define TREEHEIGHT_OFFSET       24
#define TREEHEIGHT_SHA256_OFFSET 14
#define TREEINDEX_OFFSET        28
#define TREEINDEX_SHA256_OFFSET 18

/* Used internally by the signature, keygen and verify processes */
void ts_set_up_wots_signature(struct ts_context *ctx, unsigned next_leaf);

/* Used internally to convert message hashes into FORS/hypertree locations */
void ts_convert_message_hash_to_hypertree_position(
	                       struct ts_context *ctx,
			       unsigned char *message_hash );


/* Routines to initialize the adr structure */
void ts_set_fors_root_adr(struct ts_context *ctx);
void ts_set_fors_leaf_adr(struct ts_context *ctx, int leaf_index );
void ts_set_wots_header_adr(unsigned merkle_leaf, struct ts_context *ctx);
void ts_set_merkle_adr(struct ts_context *ctx,
		   unsigned node, unsigned level, 
                   enum hash_reason typecode );
void ts_set_wots_f_adr(struct ts_context *ctx,
		   int tree_index, int leaf_index, int hash_address );

#endif /* INTERNAL_H_ */
