#if !defined(SHA2_H_)
#define SHA2_H_

/*
 * These are the prototypes for the SHA-256, SHA-512 implementations for
 * tiny sphincs.  Note that this implementation targets tiny space, rather
 * than high performance (although the performance shouldn't be that bad)
 */

#include <stddef.h>
#include <stdint.h>

#define sha256_block_size 64

/* The SHA256 context */
typedef struct SHA256_CTX {
    uint32_t h[8];                  /* State */
    uint64_t count;                 /* Number of bits processed so far */
    unsigned num;                   /* Number of bytes within the below */
                                    /* buffer */
    union {
        unsigned char data[sha256_block_size]; /* Input buffer.  This is in */
                                    /* byte vector format */
	uint32_t W[16];             /* The expanded SHA256 key schedule */
	                            /* We reuse the input buffer space, */
	                            /* rather than putting it into an auto */
	                            /* array (which is more typical) */
    } x;
} SHA256_CTX;

/* The standard init-update-final API for SHA-256 */
void ts_SHA256_init( SHA256_CTX *ctx );
void ts_SHA256_update( SHA256_CTX *ctx, const void *msg, uint64_t count );
void ts_SHA256_final( unsigned char *digest, SHA256_CTX *ctx );

/* The finaize API to SHA256, except it outputs only the first n bytes. */
/* We assume that n is a multiple of 4 no more than 32 */
void ts_SHA256_final_trunc( unsigned char *digest, SHA256_CTX *ctx, unsigned n );

/* API that compute the hash state after an input of 64 bytes, and restores */
/* that state (so we can continue wiht the update/final APIs */
void ts_SHA256_save_state( uint32_t *s, const SHA256_CTX *ctx );
void ts_SHA256_restore_state_after_64( SHA256_CTX *ctx, const uint32_t *s );



#define sha512_block_size 128

typedef struct SHA512_CTX {
    uint64_t state[8];            /* state */
    uint64_t count;               /* number of bits processed so far */
    unsigned in_buffer;           /* number of bytes within the below */
                                  /* buffer */
    union {
        unsigned char data[sha512_block_size]; /* Input buffer.  This */
                                  /* is in byte vector format */
        uint64_t W[16];           /* The expanded SHA512 key schedule */
	                          /* We reuse the input buffer space, */
	                          /* rather than putting it into an */
	                          /* auto array (which is more typical) */
    } x;
} SHA512_CTX;

/* The standard init-update-final API for SHA-512 */
void ts_SHA512_init( SHA512_CTX *ctx );
void ts_SHA512_update( SHA512_CTX *ctx, const void *msg, uint64_t count );
void ts_SHA512_final( unsigned char *digest, SHA512_CTX *ctx );

/* The finaize API to SHA512, except it outputs only the first n bytes. */
/* We assume that n is a multiple of 8 no more than 64 */
void ts_SHA512_final_trunc( unsigned char *digest, SHA512_CTX *ctx, unsigned n );

/* API that compute the hash state after an input of 128 bytes, and restores */
/* that state (so we can continue wiht the update/final APIs */
void ts_SHA512_save_state( uint64_t *s, const SHA512_CTX *ctx );
void ts_SHA512_restore_state_after_128( SHA512_CTX *ctx, const uint64_t *s );

#endif /* SHA2_H_ */
