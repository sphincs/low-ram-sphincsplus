#include <stdio.h>
#include <string.h>
#include "sha2.h"
#include "test_sphincs.h"

/*
 * This tests out the SHA512 primitive
 *
 * Obvious question: why do we have a test for the SHA-512 primitive,
 * but not the SHA-256 or SHAKE primitives?  Well, the answer is due to
 * historic reasons; the SHA-256 and SHAKE primitives were implemented
 * before the regression tests (and hence because we passed the Sphincs+
 * KATs, obviously we must have gotten those two correct).  In contrast,
 * our SHA-512 implementation was done after the regression test
 * infratructure was done - this test is here to make sure that we did
 * SHA-512 correctly (so we didn't waste time trying to figure out why
 * Sphincs+ KATs failed).
 *
 * And, once these tests were there (and passed), there was no urgent
 * reason to remove them.
 */

static int test( const unsigned char *expected_result,
                  const unsigned char *message,
                  unsigned len_message ) {
    SHA512_CTX ctx;

    for (unsigned n = 1; n <= len_message; n++) {
        ts_SHA512_init( &ctx );

        for (unsigned j=0; j<len_message; j+=n) {
            unsigned this_len = len_message - j;
            if (this_len > n) this_len = n;
            ts_SHA512_update( &ctx, &message[j], this_len );
        }

        unsigned char actual_result[ 64 ] = { 0 };
        ts_SHA512_final( actual_result, &ctx );
        if (0 != memcmp( expected_result, actual_result, 64 )) {
            printf( "   *** HASH MISMATCH\n" );
            return 0;
        }
    }

    /* Test SHA512_final_truc */
    for (int n=8; n<=64; n+=8) {
	unsigned char actual_result[64] = { 0 };
	memset( &ctx, n, sizeof ctx );  /* Fill the CTX with gibberish */
        ts_SHA512_init( &ctx );
        ts_SHA512_update( &ctx, message, len_message );
        ts_SHA512_final_trunc( actual_result, &ctx, n );
        if (0 != memcmp( expected_result, actual_result, n )) {
            printf( "   *** HASH MISMATCH\n" );
            return 0;
        }
	for (int i=n; i<64; i++) {
	    if (actual_result[i] != 0) {
                printf( "   *** SHA512_final_trunc modified bytes it shouldn't\n" );
                return 0;
	    }
        }
    }

    /* Test the SHA512_save_state API */
    if (len_message >= 128) {
        ts_SHA512_init( &ctx );
        ts_SHA512_update( &ctx, message, 128 );
	uint64_t save_state[8];
        ts_SHA512_save_state( save_state, &ctx );

        SHA512_CTX restore_ctx;
	memset( &restore_ctx, 42, sizeof restore_ctx );
        ts_SHA512_restore_state_after_128( &restore_ctx, save_state );
        ts_SHA512_update( &restore_ctx, message+128, len_message-128 );
	unsigned char actual_result[64] = { 0 };
        ts_SHA512_final( actual_result, &restore_ctx );
        if (0 != memcmp( expected_result, actual_result, 64 )) {
            printf( "   *** HASH MISMATCH\n" );
            return 0;
        }
    }

    return 1;
}

int test_sha512(int fast_flag, enum noise_level level) {
    (void)fast_flag;
    (void)level;

    // The below test vectors were extracted from NIST published values
    {
        static unsigned char message[ 3 ] = { 'a', 'b', 'c' };
        static unsigned char output[64] = {
            0xDD,0xAF,0x35,0xA1,0x93,0x61,0x7A,0xBA,
            0xCC,0x41,0x73,0x49,0xAE,0x20,0x41,0x31,
            0x12,0xE6,0xFA,0x4E,0x89,0xA9,0x7E,0xA2,
            0x0A,0x9E,0xEE,0xE6,0x4B,0x55,0xD3,0x9A,
            0x21,0x92,0x99,0x2A,0x27,0x4F,0xC1,0xA8,
            0x36,0xBA,0x3C,0x23,0xA3,0xFE,0xEB,0xBD,
            0x45,0x4D,0x44,0x23,0x64,0x3C,0xE8,0x0E,
            0x2A,0x9A,0xC9,0x4F,0xA5,0x4C,0xA4,0x9F,
        };
        if (!test( output, message, sizeof message )) return 0;
    }
    {
        static unsigned char message[] =
            "abcdefghbcdefghicdefghijdefghijkefghijkl"
            "fghijklmghijklmnhijklmnoijklmnopjklmnopq"
            "klmnopqrlmnopqrsmnopqrstnopqrstu";
        static unsigned char output[64] = {
            0x8E,0x95,0x9B,0x75,0xDA,0xE3,0x13,0xDA,
            0x8C,0xF4,0xF7,0x28,0x14,0xFC,0x14,0x3F,
            0x8F,0x77,0x79,0xC6,0xEB,0x9F,0x7F,0xA1,
            0x72,0x99,0xAE,0xAD,0xB6,0x88,0x90,0x18,
            0x50,0x1D,0x28,0x9E,0x49,0x00,0xF7,0xE4,
            0x33,0x1B,0x99,0xDE,0xC4,0xB5,0x43,0x3A,
            0xC7,0xD3,0x29,0xEE,0xB6,0xDD,0x26,0x54,
            0x5E,0x96,0xE5,0x5B,0x87,0x4B,0xE9,0x09,
        };
        if (!test( output, message, sizeof message - 1 )) return 0;
    }
    {
        static unsigned char message[111] = { 0 };
        static unsigned char output[64] = {
            0x77,0xdd,0xd3,0xa5,0x42,0xe5,0x30,0xfd,
            0x04,0x7b,0x89,0x77,0xc6,0x57,0xba,0x6c,
            0xe7,0x2f,0x14,0x92,0xe3,0x60,0xb2,0xb2,
            0x21,0x2c,0xd2,0x64,0xe7,0x5e,0xc0,0x38,
            0x82,0xe4,0xff,0x05,0x25,0x51,0x7a,0xb4,
            0x20,0x7d,0x14,0xc7,0x0c,0x22,0x59,0xba,
            0x88,0xd4,0xd3,0x35,0xee,0x0e,0x7e,0x20,
            0x54,0x3d,0x22,0x10,0x2a,0xb1,0x78,0x8c,
        };
        if (!test( output, message, sizeof message )) return 0;
    }
    {
        static unsigned char message[112] = { 0 };
        static unsigned char output[64] = {
            0x2b,0xe2,0xe7,0x88,0xc8,0xa8,0xad,0xea,
            0xa9,0xc8,0x9a,0x7f,0x78,0x90,0x4c,0xac,
            0xea,0x6e,0x39,0x29,0x7d,0x75,0xe0,0x57,
            0x3a,0x73,0xc7,0x56,0x23,0x45,0x34,0xd6,
            0x62,0x7a,0xb4,0x15,0x6b,0x48,0xa6,0x65,
            0x7b,0x29,0xab,0x8b,0xeb,0x73,0x33,0x40,
            0x40,0xad,0x39,0xea,0xd8,0x14,0x46,0xbb,
            0x09,0xc7,0x07,0x04,0xec,0x70,0x79,0x52,
        };
        if (!test( output, message, sizeof message )) return 0;
    }
    {
        static unsigned char message[113] = { 0 };
        static unsigned char output[64] = {
            0x0e,0x67,0x91,0x0b,0xcf,0x0f,0x9c,0xcd,
            0xe5,0x46,0x4c,0x63,0xb9,0xc8,0x50,0xa1,
            0x2a,0x75,0x92,0x27,0xd1,0x6b,0x04,0x0d,
            0x98,0x98,0x6d,0x54,0x25,0x3f,0x9f,0x34,
            0x32,0x23,0x18,0xe5,0x6b,0x8f,0xeb,0x86,
            0xc5,0xfb,0x22,0x70,0xed,0x87,0xf3,0x12,
            0x52,0xf7,0xf6,0x84,0x93,0xee,0x75,0x97,
            0x43,0x90,0x9b,0xd7,0x5e,0x4b,0xb5,0x44,
        };
        if (!test( output, message, sizeof message )) return 0;
    }
    {
        static unsigned char message[1000] = { 0 };
        static unsigned char output[64] = {
            0xca,0x3d,0xff,0x61,0xbb,0x23,0x47,0x7a,
            0xa6,0x08,0x7b,0x27,0x50,0x82,0x64,0xa6,
            0xf9,0x12,0x6e,0xe3,0xa0,0x04,0xf5,0x3c,
            0xb8,0xdb,0x94,0x2e,0xd3,0x45,0xf2,0xf2,
            0xd2,0x29,0xb4,0xb5,0x9c,0x85,0x92,0x20,
            0xa1,0xcf,0x19,0x13,0xf3,0x42,0x48,0xe3,
            0x80,0x3b,0xab,0x65,0x0e,0x84,0x9a,0x3d,
            0x9a,0x70,0x9e,0xdc,0x09,0xae,0x4a,0x76,
        };
        if (!test( output, message, sizeof message )) return 0;
    }

    return 1;
}
