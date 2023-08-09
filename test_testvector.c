#include <stdio.h>
#include <string.h>
#include "tiny_sphincs.h"
#include "test_sphincs.h"

/*
 * This tests out various test vectors from the reference code
 *
 * We are supposed to do the same transforms as the refence code;
 * that is, the same seed -> private/public key and the same
 * private key/optrand/message -> signature operation
 *
 * This tries to verify that both actually hold, by performing those
 * operations with fixed inputs, and comparing them against what the
 * reference code did with those same inputs (in the case of signatures, we
 * hash the signatures, and compare hashes - there's no reason to include a
 * 40k signature in our test files)
 *
 * For the public/private key generation, we use a fixed seed of
 * the form 00 01 02 03 ...
 *
 * For signing, we use the optrand value specified in with the test
 * vector
 *
 * Obvious question: why did we use an obviously nonrandom pattern
 * for key generation, but a random one for signatures?  The answer
 * is what the reference code allowed to do (without changing that
 * code); the reference code gave us an API (crypto_sign_seed_keypair)
 * that allowed us to specify the seed, so we picked a simple one.
 * In constrast, the reference code always called randombytes() to
 * get optrand (and didn't give us an option to skip it); however
 * the infrastructure did allow us to switch to a determanistic
 * version of randombytes(), so that's what we did - that version
 * gave us a random-looking pattern, so that's what we got
 */

/* Here is the set of test vectors extracted from the reference code */
static struct v {
    const char *parameter_set_name; /* Name of the parameter set */
    unsigned char public_key[64];   /* The public key that is generated */
                                    /* with the fixed seed */
    unsigned char optrand[32];      /* The optrand that was used when */
                                    /* creating the signature */
    unsigned char hash_sig[32];     /* The SHA256 hash of the signature */
                                    /* of the message "abc", using the */
                                    /* optrand and generated private key */
} vectors[] = {
#include "testvector.h"
};

// Given a parameter set name, return a key of that type
static const struct ts_parameter_set *lookup_parameter_set(const char *name) {
    if (0 == strcmp( name, "sha2_128f_simple" ))
        return &ts_ps_sha2_128f_simple;
    if (0 == strcmp( name, "shake_128f_simple" ))
        return &ts_ps_shake_128f_simple;
    if (0 == strcmp( name, "sha2_128s_simple" ))
        return &ts_ps_sha2_128s_simple;
    if (0 == strcmp( name, "shake_128s_simple" ))
        return &ts_ps_shake_128s_simple;

    if (0 == strcmp( name, "sha2_192f_simple" ))
        return &ts_ps_sha2_192f_simple;
    if (0 == strcmp( name, "shake_192f_simple" ))
        return &ts_ps_shake_192f_simple;
    if (0 == strcmp( name, "sha2_192s_simple" ))
        return &ts_ps_sha2_192s_simple;
    if (0 == strcmp( name, "shake_192s_simple" ))
        return &ts_ps_shake_192s_simple;

    if (0 == strcmp( name, "sha2_256f_simple" ))
        return &ts_ps_sha2_256f_simple;
    if (0 == strcmp( name, "shake_256f_simple" ))
        return &ts_ps_shake_256f_simple;
    if (0 == strcmp( name, "sha2_256s_simple" ))
        return &ts_ps_sha2_256s_simple;
    if (0 == strcmp( name, "shake_256s_simple" ))
        return &ts_ps_shake_256s_simple;

    printf( "*** UNRECOGNIZED PARAMETER SET %s\n", name );
    return 0;
}

/* This is an 'RNG' that gives the fixed pattern that our */
/* test vectors expect on keygen */
static int fixed_rand( unsigned char *p, size_t num_bytes ) {
    for (unsigned i=0; i<num_bytes; i++) {
        *p++ = i;
    }
    return 1;
}

/* This is an 'RNG' that gives the optrand pattern that the signature */
/* generation expects */
static unsigned char optrand_buffer[32];
static int optrand_rng( unsigned char *target, size_t num_bytes ) {
    memcpy( target, optrand_buffer, num_bytes );
    return 1;
}

/* For our SHA256 implementation, we borrow the one from Sphincs */
#include "sha2.h"

/* And here is the main code which actually runs the test */
int test_testvector(int fast_flag, enum noise_level level) {
    (void)fast_flag;  /* Test is so fast there's no point in skipping some */
                      /* parameter sets */

    for (unsigned i=0; i<sizeof vectors/sizeof *vectors; i++) {
        struct v *v = &vectors[i];

        if (level == loud) {
            printf( " Checking %s\n", v->parameter_set_name);
        }

        /* Get the parameter set */
        const struct ts_parameter_set *ps =
	                      lookup_parameter_set(v->parameter_set_name);
        if (!ps) return 0;

        /* Generate the public/private key pair */
	unsigned char private_key[128];
	unsigned char public_key[64];
        if (!ts_gen_key( private_key, public_key, ps, fixed_rand )) {
            printf( "*** ERROR GENERATING KEY\n" );
            return 0;
        }

        /* Check if it got the public key we expect */
	unsigned len_public_key = ts_size_public_key( ps );
        if (0 != memcmp( v->public_key, public_key, len_public_key )) {
            printf( "*** GENERATED DIFFERENT PUBLIC KEY FOR %s\n",
                    v->parameter_set_name );
            return 0;
        }

        /* That passed; now on to the signature */
        /* Copy the optrand somewhere the optrand_rng can get it */
        memcpy( optrand_buffer, v->optrand, 32 );

        static unsigned char message[3] = { 'a', 'b', 'c' };

        /* And sign the message; while we're generating the signature */
	/* (in pieces), hash it */
	struct ts_context ctx;
        ts_init_sign( &ctx, message, sizeof message, ps,
		      private_key, optrand_rng );
        SHA256_CTX hash_ctx;
        ts_SHA256_init( &hash_ctx );

	/* And, while we're doing that, verify the signature - no reason not */
	/* to test the verify logic at the same time */
	struct ts_context verify_ctx;
        ts_init_verify( &verify_ctx, message, sizeof message, ps,
		      public_key );

	for (;;) {
	    unsigned char buffer[ 42 ]; /* Why 42?  Well, any positive */
	                              /* integer would work */
	        /* Generate the next 42 bytes of signature */
            unsigned n = ts_sign( buffer, sizeof buffer, &ctx );
	    if (n == 0) break;   /* Hit the end of the signature */

	        /* Include what we got in the hash */
            ts_SHA256_update( &hash_ctx, buffer, n );

	        /* And pass it to the verifier */
	    if (1 != ts_update_verify( buffer, n, &verify_ctx )) {
		printf( "*** VERIFY DETECTED FAILURE FOR %s\n",
		     v->parameter_set_name );
		return 0;
	    }
	}

	    /* And create the hash of all those signature pieces */
        unsigned char hash[32];
        ts_SHA256_final( hash, &hash_ctx );

        /* Check if we got the expected hash */
        if (0 != memcmp( v->hash_sig, hash, 32 )) {
            printf( "*** GENERATED DIFFERENT SGNATURES FOR %s\n",
                    v->parameter_set_name );
            return 0;
        }

	/* And check if the signature verified */
	if (1 != ts_verify( &verify_ctx )) {
            printf( "*** SIGNATURE DID NOT VERIFY FOR %s\n",
                    v->parameter_set_name );
            return 0;
        }

        /* We're good for this parameter set */
    }

    return 1;
}
