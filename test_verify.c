#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tiny_sphincs.h"
#include "test_sphincs.h"

/* The outputs a sequence that looks sort-of random */
static int local_rand( unsigned char *buffer, size_t n ) {
    unsigned r = 0x1234;
    for (size_t i=0; i<n; i++) {
	r += (r*r) | 5;
	buffer[i] = r >> 8;
    }
    return 1;
}

static size_t total_sig_len, processed_sig_len;
static int prev_percentage;

static int do_test( const struct ts_parameter_set *ps,
                       const char* parameter_set_name, int always,
		       int fast_flag, int level, int iter ) {
        /*
	 * If we're running in fast mode, skip any parameter set that is
	 * not marked as always
	 */
    if (fast_flag && !always) return 1;

    size_t len_signature = ts_size_signature( ps );
    if (iter == 0) {
        /*
	 * For the first iteration, we're just collecting signature lengths
	 * (so that we can print the percentage completed)
	 */
        total_sig_len += len_signature;
        return 1;
    }

    if (level == loud) {
        printf( " Checking %s\n", parameter_set_name);
    }

    float current_percent = 0.0;
    float percentage_inc = 0.0;
    if (level >= whisper) {
        current_percent = 100 * (float)processed_sig_len / total_sig_len;
        percentage_inc = 100 * (float)1 / total_sig_len;
    }
    processed_sig_len += len_signature;

    /* Create a random key pair */
    unsigned char private_key[128];
    unsigned char public_key[64];
    if (!ts_gen_key( private_key, public_key, ps, local_rand )) {
        printf( "*** FAILURE GENERATING KEY\n" );
        return 0;
    }

    /* Generate a signature for a simple message */
    static const unsigned char message[3] = { 'a', 'b', 'c' };
    size_t len_message = sizeof message;
    unsigned char *s = malloc( len_signature + 1 );
    if (!s) {
	printf( "*** MALLOC FAILURE\n" );
	return 0;
    }
    struct ts_context ctx;
    ts_init_sign( &ctx, message, len_message, ps, private_key, 0 );
    if (len_signature != ts_sign( s, len_signature+1, &ctx )) {
	printf( "*** SIGNATURE WRONG SIZE\n" );
	free(s);
	return 0;
    }

    /* Make sure that it verifies */
    memset( &ctx, '?', sizeof ctx );
    ts_init_verify( &ctx, message, len_message, ps, public_key );
    if (1 != ts_update_verify( s, len_signature, &ctx ) ||
        1 != ts_verify( &ctx )) {
        printf( "*** UNMODIFIED SIGNATURE DID NOT VALIDATE\n" );
	free(s);
	return 0;
    }

    /* Make sure that passing in a too-short signature fails */
    memset( &ctx, '!', sizeof ctx );
    ts_init_verify( &ctx, message, len_message, ps, public_key );
    if (1 != ts_update_verify( s, len_signature-1, &ctx ) ||
        0 != ts_verify( &ctx )) {
        printf( "*** TOO SHORT SIGNATURE DID VALIDATE\n" );
	free(s);
	return 0;
    }

    /* Make sure that passing in a too-long signature fails */
    memset( &ctx, '@', sizeof ctx );
    ts_init_verify( &ctx, message, len_message, ps, public_key );
    if (0 != ts_update_verify( s, len_signature+1, &ctx ) ||
        0 != ts_verify( &ctx )) {
        printf( "*** TOO LONG SIGNATURE DID VALIDATE\n" );
	free(s);
	return 0;
    }

    /* Make sure that passing in a valid signature in chunks does work */
    {
	unsigned a=1, b=1, t;
	for (; a < len_signature; t=a, a=a+b, b=t) {
            memset( &ctx, b, sizeof ctx );
            ts_init_verify( &ctx, message, len_message, ps, public_key );
	    for (unsigned i=0; i<len_signature; i+=a) {
                unsigned chunk = len_signature-i;
		if (chunk > a) chunk = a;
                if (1 != ts_update_verify( s+i, chunk, &ctx )) {
                    printf( "*** INTERMEDIATE VERIFY FAILED\n" );
	            free(s);
	            return 0;
		}
	    }
            if (1 != ts_verify( &ctx )) {
                printf( "*** INCREMENTAL VERIFY FAILED\n" );
	        free(s);
	        return 0;
	    }
	}
    }

    /*
     * Now step through the signature and flip bits; verify that those
     * flipped bits prevent the signature from validating
     */
    unsigned increment = fast_flag ? 5 : 1;
    for (size_t offset = 0; offset < len_signature; offset += increment) {
        if (level >= whisper) {
            /* Update the percentage completed if needed */
            int this_percentage = (int)current_percent;
            if (this_percentage != prev_percentage) {
                printf( "%d%%\r", this_percentage );
                fflush(stdout);
                prev_percentage = this_percentage;
            }
            current_percent += increment * percentage_inc;
        }

        unsigned bit_increment = fast_flag ? 8 : 1;
        for (unsigned bit = 0; bit < 8; bit += bit_increment) {
            s[offset] ^= (1 << bit);

            memset( &ctx, offset+bit, sizeof ctx );
            ts_init_verify( &ctx, message, len_message, ps, public_key );

            /* Make sure that it doesn't verify */
            if (0 != ts_update_verify( s, len_signature, &ctx ) ||
                 0 != ts_verify( &ctx )) {
                printf( "*** SIGNATURE VALIDATED FOR MODIFIED SIGNATURE\n" );
		free(s);
                return 0;
            }

            s[offset] ^= (1 << bit);
        }
    }

    /* Make sure that the message is back to how we found it */
    ts_init_verify( &ctx, message, len_message, ps, public_key );
    if (1 != ts_update_verify( s, len_signature, &ctx ) ||
        1 != ts_verify( &ctx )) {
        printf( "*** UNMODIFIED SIGNATURE DID NOT VALIDATE\n" );
	free(s);
	return 0;
    }

    /* Make sure that an incorrect message does not validate */
    static const unsigned char wrong_message[3] = { 'd', 'e', 'f' };
    size_t len_wrong_message = sizeof wrong_message;
    ts_init_verify( &ctx, wrong_message, len_wrong_message, ps, public_key );
    if (0 != ts_update_verify( s, len_signature, &ctx ) ||
        0 != ts_verify( &ctx )) {
        printf( "*** INCORRECT MESSAGE DID VALIDATE\n" );
	free(s);
	return 0;
    }
    free(s);

    return 1;
}

#define CONCAT( A, B ) A##B
#define RUN_TEST(PARM_SET, always) {                                \
    const struct ts_parameter_set *ps = &CONCAT( ts_ps_, PARM_SET ); \
    if (!do_test( ps, #PARM_SET, always, fast_flag, level, iter )) { \
        return 0;                                                   \
    }                                                               \
}

int test_verify(int fast_flag, enum noise_level level) {
    total_sig_len = 0;
    processed_sig_len = 0;
    prev_percentage = -1;
    for (unsigned iter=0; iter <= 1; iter++) {

        /*
         * Iterate through all the defined parameter sets
         * The ones marked '1' we always do; we do the '0'
         * ones only in '-full' mode
         */

        /* L1 parameter sets */
        RUN_TEST( sha2_128s_simple, 1 );
        RUN_TEST( sha2_128f_simple, 1 );
        RUN_TEST( shake_128s_simple, 1 ); 
        RUN_TEST( shake_128f_simple, 0 );

        /* L3 parameter sets */
        RUN_TEST( sha2_192s_simple, 1 );
        RUN_TEST( sha2_192f_simple, 0 );
        RUN_TEST( shake_192s_simple, 1 );
        RUN_TEST( shake_192f_simple, 0 );

        /* L5 parameter sets */
        RUN_TEST( sha2_256s_simple, 1 );
        RUN_TEST( sha2_256f_simple, 0 );
        RUN_TEST( shake_256s_simple, 1 );
        RUN_TEST( shake_256f_simple, 0 );
    }

    return 1; 
}
