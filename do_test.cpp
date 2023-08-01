#include <stdio.h>
extern "C" {
#include "tiny_sphincs.h"
#include "sha2.h"
}
#include "do_stack_test.h"
#include "stack.h"

#include "parallel-sphincsplus-main/api.h"  /* For testing */

#define SHA256_128F   0
#define SHA256_128S   0
#define SHAKE256_128F 1
#define SHAKE256_128S 0
#define SHAKE256_192F 0
#define SHAKE256_192S 0
#define SHAKE256_256F 0
#define SHAKE256_256S 0

static int ts_rand_function( unsigned char *p, size_t n) {
    for (size_t i=0; i<n; i++) {
	p[i] = i;
    }
    return 1;
}
static sphincs_plus::success_flag ref_rand_function( void *raget, size_t n ) {
    (void)ts_rand_function( static_cast<unsigned char *>(raget), n );
    return sphincs_plus::success;
}

int main(void) {
    struct ts_context ctx;
    unsigned char private_key[128];
    for (int i=0; i<128; i++) private_key[i] = i;

    /* Generate the known good signature */
#if SHA256_128F
    sphincs_plus::key_sha256_128f_simple ref;
#elif SHA256_128S
    sphincs_plus::key_sha256_128s_simple ref;
#elif SHAKE256_128F
    sphincs_plus::key_shake256_128f_simple ref;
#elif SHAKE256_128S
    sphincs_plus::key_shake256_128s_simple ref;
#elif SHAKE256_192F
    sphincs_plus::key_shake256_192f_simple ref;
#elif SHAKE256_192S
    sphincs_plus::key_shake256_192s_simple ref;
#elif SHAKE256_256F
    sphincs_plus::key_shake256_256f_simple ref;
#elif SHAKE256_256S
    sphincs_plus::key_shake256_256s_simple ref;
#else
#error Pick a parameter set
#endif
    ref.set_num_thread(1);  /* Turn off parallezation - it confuses debugs */
    ref.set_private_key(private_key);
    unsigned char message[] = { 'F', 'o', 'o' };
    auto sig = ref.sign(message, 3, 0);
    unsigned len_sig = ref.len_signature();

#if 0
    for (int i=0; i<LEN_OUTPUT; i++) {
	printf( "%x: ", i );
	for (int j=0; j<16; j++) printf( "%x ", (sig.get())[16*i+j] );
	printf( "\n" );
    }
    printf( "\n" );
#endif
    printf( "\n----\n" );

    /* Generate the signature to compare */
    const struct ts_parameter_set *ps =
#if SHA256_128F
                  &ts_ps_sha2_128f_simple;
#elif SHA256_128S
                  &ts_ps_sha2_128s_simple;
#elif SHAKE256_128F
                  &ts_ps_shake_128f_simple;
#elif SHAKE256_128S
                  &ts_ps_shake_128s_simple;
#elif SHAKE256_192F
                  &ts_ps_shake_192f_simple;
#elif SHAKE256_192S
                  &ts_ps_shake_192s_simple;
#elif SHAKE256_256F
                  &ts_ps_shake_256f_simple;
#elif SHAKE256_256S
                  &ts_ps_shake_256s_simple;
#else
#error Pick a parm set
#endif

    ts_init_sign( &ctx,
		  "Foo", 3,
		  ps,
                  private_key,
		  0 );
    unsigned i;
    for (i=0;; i++) {
	unsigned char c[1];
	if (1 != ts_sign( c, 1, &ctx )) break;
	if (i > len_sig) {
	    printf( "*** SIG TOO LONG\n" );
	    return 0;
	}
	if (c[0] != (sig.get())[i]) {
	    printf( "*** FIRST DIFF AT %d (%x)\n", i, i );
	    return 0;
	}
    }

    printf( "Generated %d out of %d bytes\n", i, len_sig );

    /* Print the sizes of various objects */
    printf( "priv_key = %u pub_key = %u sig = %u\n",
                ts_size_private_key( ps ),
                ts_size_public_key( ps ),
                ts_size_signature( ps ) );

    /* Generate a public key using the standard implementation */
    if (!ref.generate_key_pair(ref_rand_function )) {
	printf( "Ref gen key failed\n" );
	return 0;
    }
    const unsigned char *ref_priv_key = ref.get_private_key();
    for (unsigned i=0; i<ref.len_private_key(); i++) {
	printf( "%x ", ref_priv_key[i] );
    }
    printf( "\n" );

    /* Now generate a public key using the tiny sphincs implementation */
    unsigned char ts_priv_key[4*32];
printf( "Generating keypair\n" ); /* DEBUG HACK */
    if (0 == ts_gen_key( ts_priv_key, 0, ps, ts_rand_function )) {
	printf( "Gen key failed\n" );
	return 0;
    }
    for (unsigned i=0; i<ts_size_private_key(ps); i++) {
	printf( "%x ", ts_priv_key[i] );
    }
    printf( "\n" );

    printf( "Context size = %u\n", (unsigned)sizeof (struct ts_context));
    /* Now measure the stack used */
    init_stack();
printf( "Did init_stack\n" );
    do_stack_test(ps);
printf( "Did do_stack_test\n" );
    unsigned n = measure_stack();

    printf( "Space used for signature = %u\n", n );

    /* Now measure the stack used for keygen */
    init_stack();
    do_stack_test_keygen(ps);
    n = measure_stack();

    printf( "Space used for keygen = %u\n", n );

    return 0;
}
