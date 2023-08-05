/*
 * This file contains the code that (along with get_space2.c and stack.c) measures
 * how much RAM the key generation, signature generation and signature verification
 * processes uses.
 *
 * It works by calling init_stack() (defined in stack.c) to set things up, calling
 * a function that allocates on the stack everything that is needed (e.g. the context)
 * and performing the operation (these functions are defined in get_space2.c) and then
 * calling measure_stack() (also defined in stack.c) to find out how much stack was
 * used during the process
 *
 * We place the various functions in separate files to prevent the compiler from
 * inlining them (which would mess up the measurements)
 */

#include <stdlib.h>
#include "tiny_sphincs.h"
#include "get_space.h"
#include "get_space2.h"
#include "stack.h"

/*
 * When we create a key, we need to provide a 'source of randomness'
 * We don't care about security here (and the values don't change the amount of
 * RAM used) and so we provide a trivial one
  */
static int fake_rand(unsigned char *s, size_t n) {
    while (n--) {
        *s++ = n+1;
    }
    return 1;
}

/*
 * This measures the amount of RAM used during a key generation call
 */
unsigned get_keygen_space(const struct ts_parameter_set *ps) {
    init_stack();
    run_keygen(ps);
    return measure_stack();
}

/*
 * This measures the amount of RAM used during a signature generation
 */
unsigned get_sig_space(const struct ts_parameter_set *ps) {
    /* Generate a private key (we need one to sign) */
    unsigned char private_key[128];
    ts_gen_key( private_key, 0, ps, fake_rand );

    /* And perform the actual measurement */
    init_stack();
    run_sign(ps, private_key);
    return measure_stack();
}

/*
 * This measures the amount of RAM used during a signature verification
 */
unsigned get_ver_space(const struct ts_parameter_set *ps) {
    /* Generate a public key and a valid signature; we need both to verify */
    unsigned char public_key[64];
    unsigned char *sig = get_sig_and_public_key( ps, public_key, "abc", 3 );
    if (!sig) return 0;

    /* The signature verification will need to know how long the signature is */
    unsigned sig_len = ts_size_signature( ps );

    /* And perform the actual measurement */
    init_stack();
    int success = run_verify(ps, public_key, "abc", 3, sig, sig_len);
    unsigned space = measure_stack();
    free(sig);

    /* If the verification failed, then something went wrong (the signature */
    /* is supposed to be valid) */
    if (!success) return 0;
    else return space;
}
