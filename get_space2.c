/*
 * This file contains the code that (along with get_space.c and stack.c) measures
 * how much RAM the key generation, signature generation and signature verification
 * processes uses.
 *
 * The routines within get_space.c measures the stack usage of the routines in
 * this file.  Hence, what we do is allocate as automatics (which on my compiler
 * allocates them on the stack) anything we want to include (for example, the
 * context), and then calling the API which we are measuring (which would allocate
 * some more stack for its own purposes).
 * For things that we don't want to count against the RAM usage, we allocate them
 * as static.
 *
 * We place the various functions in separate files to prevent the compiler from
 * inlining them (which would mess up the measurements)
 */
#include <stdlib.h>
#include "tiny_sphincs.h"
#include "get_space2.h"

/*
 * When we create a key, we need to provide a 'source of randomness'
 * We don't care about security here (and the values don't change the amount of
 * RAM used) and so we provide a trivial one
*/
static int fake_rand(unsigned char *s, size_t n) {
    while (n--) {
        *s++ = n;
    }
    return 1;
}

/*
 * This is used to measure the amount of RAM used by the key generation process
 * Note that the amount of space used by the private key (or the public
 * key) is not counted.
 */
void run_keygen(const struct ts_parameter_set *ps) {
    static unsigned char private_key[128]; /* We don't count the space */

    ts_gen_key( private_key, 0, ps, fake_rand );
}

/*
 * This is used to measure the amount of RAM when generating a signature
 */
void run_sign(const struct ts_parameter_set *ps, const unsigned char *priv_key) {
    struct ts_context ctx;
    ts_init_sign( &ctx, "abc", 3, ps, priv_key, 0 );
    for (;;) {
	static unsigned char c;   /* We don't count the buffer space */
        if (1 != ts_sign( &c, 1, &ctx ))
	    break;
    }
}

/*
 * This is used to measure the amount of RAM used when verify a signature
 * This returns 1 if the signature verified, 0 if it didn't
 */
int run_verify(const struct ts_parameter_set *ps,
	       const unsigned char *public_key,
	       const void *message, int len_message,
	       const unsigned char *sig, unsigned len_sig) {
    struct ts_context ctx;

    ts_init_verify( &ctx, message, len_message, ps, public_key );
    (void)ts_update_verify( sig, len_sig, &ctx );  /* We have the */
	    /* entire signature, so give it to the API all at once */
    return ts_verify( &ctx );
}

/*
 * This generates a public/private key pair, and a valid signature for
 * the given message.  Note that it malloc's space for the signature;
 * the caller is expected to free() it
 *
 * This isn't used directly to measure RAM; instead, the verify test
 * uses this to come up with a valid public key/message/signature set
 * to pass to the run_verify routine
 */
unsigned char *get_sig_and_public_key( const struct ts_parameter_set *ps,
		unsigned char *public_key, const void *message,
	       	unsigned len_message ) {
    unsigned char private_key[128];
    ts_gen_key( private_key, public_key, ps, fake_rand );

    unsigned sig_len = ts_size_signature( ps );
    unsigned char *sig = malloc(sig_len);
    if (!sig) return 0;  /* Malloc failure - go buy a real computer */

    struct ts_context ctx;
    ts_init_sign( &ctx, message, len_message, ps, private_key, fake_rand );
    ts_sign( sig, sig_len, &ctx );

    return sig;
}
