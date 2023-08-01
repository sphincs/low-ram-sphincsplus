/*
 * This is the API for the tiny-sphincs implementation
 * It is designed to use minimal data space during the signing process
 */
#if !defined( TINY_SPHINCS_H_ )
#define TINY_SPHINCS_H_

#include <stdint.h>
#include <stddef.h>
#include "fips202.h"
#include "sha2.h"
#include "tune.h"

/*
 * The maximum size of a hash that we use
 */
#if TS_SUPPORT_L5 
#define TS_MAX_HASH 32  /* Full hash size */
#elif TS_SUPPORT_L3
#define TS_MAX_HASH 24  /* L3 hash size */
#else
#define TS_MAX_HASH 16  /* L1 hash size */
#endif

#define TS_MAX_WOTS_DIGITS (2*TS_MAX_HASH + 3)
#define TS_MAX_FORS 35  /* The maximum number of FORS trees we have */

/* We could make these depend on the supported parameter set */
#if TS_SUPPORT_S
#if TS_SUPPORT_L5 || TS_SUPPORT_L3
#define TS_MAX_T         14 /* The maximum height of a FORS tree */
#else
#define TS_MAX_T         12 /* The maximum height of a FORS tree */
#endif
#else
#if TS_SUPPORT_L5
#define TS_MAX_T          9
#elif TS_SUPPORT_L3
#define TS_MAX_T          8
#else
#define TS_MAX_T          6
#endif
#endif

#if TS_SUPPORT_S
#define TS_MAX_MERKLE_H   9 /* The maximum height of a Merkle tree */
#else
#if TS_SUPPORT_L5
#define TS_MAX_MERKLE_H   4
#else
#define TS_MAX_MERKLE_H   3
#endif
#endif

#if TS_SUPPORT_SHAKE
#define ADR_SIZE         32 /* Size of a standard ADR structure */
#else
#define ADR_SIZE         22 /* We deal only with SHA2 ADR structures */
#endif

struct ts_parameter_set; /* The user needn't know the ugly details */

/*
 * This allows the incremental evaluation of a T function
 */
union t_iterator {
#if TS_SUPPORT_SHAKE
    SHAKE256_CTX shake256_simple;
#endif
#if TS_SUPPORT_SHA2
    SHA256_CTX sha2_L1_simple;
#endif
#if TS_SUPPORT_SHA2 && (TS_SUPPORT_L3 || TS_SUPPORT_L5)
    SHA512_CTX sha2_L35_simple;
#endif
};

/*
 * This is the Tiny Sphincs+ context structure.  It's main job is to hold
 * state while we're incrementally generating/validating a signature.
 * Some of these fields are also used as a scratch pad during the operation
 * (as it turns out reserving space here is sometimes more efficient than
 * using an automatic)
 */
struct ts_context {
    const struct ts_parameter_set *ps;  /* The parameter set */
    const unsigned char *public_key;    /* The public key.  If this is */
                                        /* also a private key, the */
                                        /* private portions will occur */
                                        /* at a negative offset */

    /* This tells us where we are in the signing/verification process */
    enum {
	ts_sign_state, /* These are the states for the signing process */
        ts_fors_leaf, /* Working on a FORS leaf node */
        ts_fors,    /* Working on the FORS trees */
	ts_wots,    /* Working on a WOTS signature */
	ts_merkle,  /* Working on a merkle authentication path */
	ts_done,    /* We finished */

	ts_verify_state, /* These are the states for the verification pro */
	ts_verify_init, /* Just been initialized, waiting for R */
	ts_verify_fors_leaf, /* Waiting for a FORS leaf node */
	ts_verify_fors, /* Waiting for a FORS auth path node */
	ts_verify_wots, /* Processing a WOTS signature */
	ts_verify_merkle, /* Processing a merkle authentication path */
	ts_verify_success, /* Verification successful */
	ts_verify_fail /* Verification failed */
    } state;
    unsigned char buffer[TS_MAX_HASH]; /* The hash that has just been */
                                     /* output (for signing) or we */
                                     /* have recieved (for verif) */
    unsigned char buffer_offset;     /* Where in the current buffer */
                                     /* we are */

    unsigned char hypertree_level;   /* Which level within the hypertree */
                                     /* we are processing now (FORS == */
                                     /* level 0) */
    unsigned char fors_tree;         /* Which FORS tree we are on */
                                     /* 0 if we're processing hypertree */
    unsigned char merkle_level;      /* What level of Merkle/FORS tree */
                                     /* we are processing now */
    unsigned char adr[ADR_SIZE];     /* The ADR structure, for general */
                                     /* use */
    unsigned short auth_path_node;   /* What leaf we're generating an */
                                     /* authentication path for */
    unsigned short fors_keypair_addr; /* leaf of the bottom Merkle tree */
                                     /* if we're processing a FORS tree */
                                     /* 0 if we're going through the */
                                     /* hypertree */
    uint64_t tree_address;           /* For the Merkle tree we're */
    				     /* working on now */

    unsigned char auth_path_buffer[TS_MAX_HASH]; /* Intermediate value */
                                     /* for processing Merkle nodes */

    union t_iterator big_iter;       /* Used to combine FORS roots and */
                                     /* WOTS heads */
    union t_iterator small_iter;     /* Used for everything else */

#if TS_SUPPORT_SHA2 && TS_SHA2_OPTIMIZATION
    /* These store the SHA2 state after hashing the public seed */
    /* They are optional, but speed up SHA2 processing a lot */
    uint32_t prehash_sha256[8];
#if TS_SUPPORT_L5 || TS_SUPPORT_L3
    uint64_t prehash_sha512[8];
#endif
#endif

    /* Storage for holding information specific to a state */
    union {
	struct {
	    unsigned short fors_node[TS_MAX_FORS];
	    unsigned char stack[(TS_MAX_T-1) * TS_MAX_HASH];
	} fors;   /* When we're outputing FORS nodes */
	struct {
	    unsigned char digit;
	    unsigned char digits[TS_MAX_WOTS_DIGITS];
	} wots;   /* When we're outputing a WOTS signature */
	struct {
	    unsigned char buffer[TS_MAX_HASH];
	    unsigned char stack[(TS_MAX_MERKLE_H-1) * TS_MAX_HASH];
	} merkle; /* Used when we're generating a Merkle tree */
	struct {
	    const void *message;
	    size_t len_message;
	} verify; /* Used when we're starting a signature verify */
    } x;
};

/*
 * This generates a public/private keypair
 * Parameters:
 * private_key - where to place the private key.  This is assumed to be
 *               ts_size_private_key(ps) bytes long
 * public_key -  where to place the public key.  This is optional (it's
 *               not that difficult to extract the public key from the
 *               private one).  If provided, this should be
 *               ts_size_public_key(ps) bytes long
 * ps -		 specifies the parameter set
 * random_function - the function to call to get secure randomness (which,
 * 		 of course, this needs).  The function should fill the
 * 		 buffer with the given number of random bytes (and return
 * 		 1), or return 0 on failure.
 * This returns 1 on success, 0 on failure
 */
int ts_gen_key( unsigned char *private_key,
		unsigned char *public_key,
		const struct ts_parameter_set *ps,
	        int (*random_function)(unsigned char *, size_t) );

/*
 * This starts out the signing process, initializing the context structure
 * (and doing the work we can do before we output any part of the
 * signature)
 * Parameters:
 * ctx -         The context structure we'll use to hold the state of the
 *               signing process
 * message -     The message we're signing
 * len_message - The number of bytes in the message
 * ps -		 specifies the parameter set
 * private_key - The private key to sign with.  This needs to be valid
 *               during the entire signature process
 * random_function - the function to call to get secure randomness.  The
 * 		 function should fill the buffer with the given number of
 * 		 random bytes (and return 1), or return 0 on failure.
 * 		 If NULL, this uses the Sphincs+ deterministic signing method
 */
void ts_init_sign( struct ts_context *ctx,
                   const void *message, size_t len_message,
                   const struct ts_parameter_set *ps,
                   const unsigned char *private_key,
	           int (*random_function)(unsigned char *, size_t) );

/*
 * This generates the next N bytes of the signature.  It returns the
 * number of bytes actually generated.  It'll be the full N until we
 * hit the end of the signature
 * Parameters:
 * dest -        The buffer to receive the next n bytes of the signature 
 * n -           Number of bytes of signature to generate this time
 * ctx -         The context structure that holds the state of the
 *               signing process
 * This returns the number of bytes it placed into dest; 0 if we reached
 * the end of the signature
 */
unsigned ts_sign( unsigned char *dest, unsigned n,
                  struct ts_context *ctx );

/*
 * This starts the signature verification process, initializing the
 * context structure
 * Parameters:
 * ctx -         The context structure we'll use to hold the state of the
 *               verification process
 * message -     The message we're verifying.  Note that this buffer needs
 *               to be valid during the entire verification process
 * len_message - The number of bytes in the message
 * ps -		 specifies the parameter set
 * public_key -  The public key to use.  This needs to be valid during the
 *               entire verification process
 */
void ts_init_verify( struct ts_context *ctx,
                   const void *message, size_t len_lenssage,
                   const struct ts_parameter_set *ps,
                   const unsigned char *public_key );

/*
 * This processes the next N byte of the signature to verify
 * If this notices a fatal error midway, this returns 0 - in that
 * case, the application may choose to abort the verification process
 * Parameters:
 * sig -         The next n bytes of the signature we're verifying
 * n -           Number of bytes of signature this time
 * ctx -         The context structure that holds the state of the
 *               verification process
 * This returns 1 if the signature looks good up until now; 0 if we
 * detected that the signature couldn't possibly be valid
 */
int ts_update_verify( const unsigned char *sig, unsigned n,
		      struct ts_context *ctx );

/*
 * This finishes the signature verify process.  It returns 1 if the
 * signature verifies
 */
int ts_verify( struct ts_context *ctx );

/*
 * The sizes of various things
 */
unsigned ts_size_private_key( const struct ts_parameter_set *ps );
unsigned ts_size_public_key( const struct ts_parameter_set *ps );
unsigned ts_size_signature( const struct ts_parameter_set *ps );

/*
 * And all the supported parameter sets
 */
#if TS_SUPPORT_SHAKE
extern const struct ts_parameter_set ts_ps_shake_128f_simple;
#endif
#if TS_SUPPORT_SHAKE && TS_SUPPORT_S
extern const struct ts_parameter_set ts_ps_shake_128s_simple;
#endif
#if TS_SUPPORT_SHAKE && (TS_SUPPORT_L3 || TS_SUPPORT_L5)
extern const struct ts_parameter_set ts_ps_shake_192f_simple;
#endif
#if TS_SUPPORT_SHAKE && TS_SUPPORT_S && (TS_SUPPORT_L3 || TS_SUPPORT_L5)
extern const struct ts_parameter_set ts_ps_shake_192s_simple;
#endif
#if TS_SUPPORT_SHAKE && TS_SUPPORT_L5
extern const struct ts_parameter_set ts_ps_shake_256f_simple;
#endif
#if TS_SUPPORT_SHAKE && TS_SUPPORT_S && TS_SUPPORT_L5
extern const struct ts_parameter_set ts_ps_shake_256s_simple;
#endif

#if TS_SUPPORT_SHA2
extern const struct ts_parameter_set ts_ps_sha2_128f_simple;
#endif
#if TS_SUPPORT_SHA2 && TS_SUPPORT_S
extern const struct ts_parameter_set ts_ps_sha2_128s_simple;
#endif

#if TS_SUPPORT_SHA2 && (TS_SUPPORT_L5 || TS_SUPPORT_L3)
extern const struct ts_parameter_set ts_ps_sha2_192f_simple;
#endif
#if TS_SUPPORT_SHA2 && (TS_SUPPORT_L5 || TS_SUPPORT_L3) & TS_SUPPORT_S
extern const struct ts_parameter_set ts_ps_sha2_192s_simple;
#endif

#if TS_SUPPORT_SHA2 && TS_SUPPORT_L5
extern const struct ts_parameter_set ts_ps_sha2_256f_simple;
#endif
#if TS_SUPPORT_SHA2 && TS_SUPPORT_L5 && TS_SUPPORT_S
extern const struct ts_parameter_set ts_ps_sha2_256s_simple;
#endif

#endif /* TINY_SPHINCS_H_ */
