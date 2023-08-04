/*
 * SHA-512
 * Implementation derived from LibTomCrypt (Tom St Denis)
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtomcrypt.org
 */

#include <string.h>
#include "sha2.h"
#include "endian.h"

/* 
 * Do not change these #define values. They are defined to appease
 * static analysis.
 */
#define SHA512_S_SIZE           8
#define SHA512_K_SIZE	        80
#define SHA512_FINALCOUNT_SIZE	16

static const unsigned long long K[SHA512_K_SIZE] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

/* Various logical functions */
#define ROR64c(x, y) ( ((((uint64_t)(x))>>((y)&63)) | ((uint64_t)(x)<<(64-((y)&63)))))
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (z ^ ((x^z) & (y^z)))
#define S(x, n)         ROR64c(x, n)
#define R(x, n)         (((x))>>(n))
#define Sigma0(x)       (S(x, 28) ^ S(x, 34) ^ S(x, 39))
#define Sigma1(x)       (S(x, 14) ^ S(x, 18) ^ S(x, 41))
#define Gamma0(x)       (S(x, 1) ^ S(x, 8) ^ R(x, 7))
#define Gamma1(x)       (S(x, 19) ^ S(x, 61) ^ R(x, 6))

static void sha512_compress (SHA512_CTX * ctx, const void *buf) {
    uint64_t S[SHA512_S_SIZE], t0, t1;
    int i;

    /* copy state into S */
    for (i = 0; i < SHA512_S_SIZE; i++) {
        S[i] = ctx->state[i];
    }

    /*
     * We've been asked to perform the hash computation on this 1024-bit 
     * string. SHA512 interprets that as an array of 16 bigendian 64 bit
     * numbers; copy it, and convert it into 16 uint64_t's of the CPU's
     * native format
     */
    const unsigned char *p = (const unsigned char*)buf;
    for (i=0; i<16; i++) {
        ctx->x.W[i] = ts_bytes_to_ull(p, 8);
        p += 8;
    }

    /* Compress */
    for (i = 0; i < SHA512_K_SIZE; i++) {
	 if (i >= 16) {
             ctx->x.W[i&15] = Gamma1(ctx->x.W[(i - 2)&15]) +
		                     ctx->x.W[(i - 7)&15] +
			      Gamma0(ctx->x.W[(i - 15)&15]) +
			             ctx->x.W[i&15];
	}
        t0 = S[7] + Sigma1(S[4]) + Ch(S[4], S[5], S[6]) + K[i] + ctx->x.W[i&15];
        t1 = Sigma0(S[0]) + Maj(S[0], S[1], S[2]);
        S[7] = S[6];
        S[6] = S[5];
        S[5] = S[4];
        S[4] = S[3] + t0;
        S[3] = S[2];
        S[2] = S[1];
        S[1] = S[0];
        S[0] = t0 + t1;
    }

    /* feedback */
    for (i = 0; i < SHA512_S_SIZE; i++) {
        ctx->state[i] += S[i];
    }
}

void SHA512_init (SHA512_CTX *ctx)
{
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;

    ctx->count = 0;
    ctx->in_buffer = 0;
}

void SHA512_update( SHA512_CTX *ctx, const void *src, uint64_t input_count ) {
    const unsigned char *p = (const unsigned char *)src;
    ctx->count += 8 * input_count;

    while (input_count) {
        unsigned int this_step = 128 - ctx->in_buffer;
        if (this_step > input_count) this_step = input_count;
	const unsigned char *this_block;
	if (this_step == 128) {
            this_block = p;  /* The entire block comes directly from the */
                             /* data stream.  Compress it without copying */
	} else {	
            memcpy( &ctx->x.data[ctx->in_buffer], p, this_step );

            if (this_step + ctx->in_buffer < 128) {
                ctx->in_buffer += this_step;
                break;
            }
            this_block = ctx->x.data;  /* We had to assemble this block in */
	                        /* the data buffer - compress it from there */
	}

        p += this_step;
        input_count -= this_step;
        ctx->in_buffer = 0;

        sha512_compress( ctx, this_block );
    }
}

/*
 * Add padding and return the message digest.
 */
void SHA512_final( unsigned char *digest, SHA512_CTX *ctx ) {
    SHA512_final_trunc( digest, ctx, 64 );
}

void SHA512_final_trunc( unsigned char *digest, SHA512_CTX *ctx, unsigned n ) {
    unsigned char finalcount[SHA512_FINALCOUNT_SIZE];

    ts_ull_to_bytes(finalcount, ctx->count, SHA512_FINALCOUNT_SIZE);

    SHA512_update(ctx, "\200", 1);

    if (ctx->in_buffer > 112) {
        SHA512_update(ctx, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
    }
    memset( ctx->x.data + ctx->in_buffer, 0, 112 - ctx->in_buffer );
    ctx->in_buffer = 112;
    SHA512_update(ctx, finalcount, SHA512_FINALCOUNT_SIZE);  /* Should cause a compress */

    /*
     * The final state is an array of uint64_t's; place them as a series
     * of bigendian 8-byte words onto the output
     */ 
    for (unsigned i=0; i<n/8; i++) {
        ts_ull_to_bytes( digest + 8*i, ctx->state[i], 8 );
    }
}

void SHA512_save_state( uint64_t *s, const SHA512_CTX *ctx ) {
    for (unsigned i=0; i<8; i++) {
	s[i] = ctx->state[i];
    }
}

void SHA512_restore_state_after_128( SHA512_CTX *ctx, const uint64_t *s ) {
    for (unsigned i=0; i<8; i++) {
	ctx->state[i] = s[i];
    }
    ctx->count = 8*sha512_block_size; /* We've processed 128 bytes */
    ctx->in_buffer = 0;    /* and we're at the start of the next block */
}
