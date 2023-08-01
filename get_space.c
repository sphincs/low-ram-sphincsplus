#include <stdlib.h>
#include "tiny_sphincs.h"
#include "get_space.h"
#include "get_space2.h"
#include "stack.h"

static int fake_rand(unsigned char *s, size_t n) {
    while (n--) {
        *s++ = n+1;
    }
    return 1;
}

unsigned get_keygen_space(const struct ts_parameter_set *ps) {
    init_stack();
    run_keygen(ps);
    return measure_stack();
}

unsigned get_sig_space(const struct ts_parameter_set *ps) {
    /* Generate a private key (we need one to sign) */
    unsigned char private_key[128];
    ts_gen_key( private_key, 0, ps, fake_rand );

    init_stack();
    run_sign(ps, private_key);
    return measure_stack();
}

unsigned get_ver_space(const struct ts_parameter_set *ps) {
    /* Generate a private/public keypair (we need one to sign/verify) */
    unsigned char public_key[64];
    unsigned char *sig = get_sig_and_public_key( ps, public_key, "abc", 3 );

    unsigned sig_len = ts_size_signature( ps );

    init_stack();
    int success = run_verify(ps, public_key, "abc", 3, sig, sig_len);
    unsigned space = measure_stack();
    free(sig);
    if (!success) return 0;
    else return space;
}
