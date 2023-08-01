#include <stdlib.h>
#include "tiny_sphincs.h"
#include "get_space2.h"

static int fake_rand(unsigned char *s, size_t n) {
    while (n--) {
        *s++ = n;
    }
    return 1;
}

void run_keygen(const struct ts_parameter_set *ps) {
    static unsigned char private_key[128]; /* We don't count the space */
    static unsigned char public_key[64];   /* for the public and private */
                                           /* keys */

    ts_gen_key( private_key, public_key, ps, fake_rand );
}

void run_sign(const struct ts_parameter_set *ps, const unsigned char *priv_key) {
    struct ts_context ctx;
    ts_init_sign( &ctx, "abc", 3, ps, priv_key, fake_rand );
    for (;;) {
	static unsigned char c;
        if (1 != ts_sign( &c, 1, &ctx ))
	    break;
    }
}

int run_verify(const struct ts_parameter_set *ps,
	       const unsigned char *public_key,
	       const void *message, int len_message,
	       const unsigned char *sig, unsigned len_sig) {
    struct ts_context ctx;

    ts_init_verify( &ctx, message, len_message, ps, public_key );
    (void)ts_update_verify( sig, len_sig, &ctx );
    return ts_verify( &ctx );
}

unsigned char *get_sig_and_public_key( const struct ts_parameter_set *ps,
		unsigned char *public_key, const void *message,
	       	unsigned len_message ) {
    unsigned char private_key[128];
    ts_gen_key( private_key, public_key, ps, fake_rand );

    unsigned sig_len = ts_size_signature( ps );
    unsigned char *sig = malloc(sig_len);
    if (!sig) return 0;

    struct ts_context ctx;
    ts_init_sign( &ctx, message, len_message, ps, private_key, fake_rand );
    ts_sign( sig, sig_len, &ctx );

    return sig;
}
