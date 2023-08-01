#include <stddef.h>
#include "tiny_sphincs.h"

/*
 * The parameter set functions used by a SHA2 parameter set
 */

void ts_sha2_L1_prf_msg( unsigned char *output,
	             const unsigned char *opt_buffer,
		     const unsigned char *message, size_t len_message,
	             struct ts_context *ctx);
void ts_sha2_L35_prf_msg( unsigned char *output,
	             const unsigned char *opt_buffer,
		     const unsigned char *message, size_t len_message,
	             struct ts_context *ctx);
void ts_sha2_L1_hash_msg( unsigned char *output, size_t len_output,
		     const unsigned char *randomness,
		     const unsigned char *message, size_t len_message,
	             struct ts_context *ctx);
void ts_sha2_L35_hash_msg( unsigned char *output, size_t len_output,
		     const unsigned char *randomness,
		     const unsigned char *message, size_t len_message,
	             struct ts_context *ctx);
void ts_sha2_prf( unsigned char *output, struct ts_context *ctx);
void ts_sha2_f_simple( unsigned char *output,
	             const unsigned char *inblock,
	             struct ts_context *ctx);
void ts_sha2_L1_init_t_simple( union t_iterator *t,
		     struct ts_context *ctx );
void ts_sha2_L1_next_t_simple( union t_iterator *t, const unsigned char *input,
		     const struct ts_context *ctx );
void ts_sha2_L1_final_t_simple(unsigned char *output, union t_iterator *t,
		     const struct ts_context *ctx );
void ts_sha2_L35_init_t_simple( union t_iterator *t,
		     struct ts_context *ctx );
void ts_sha2_L35_next_t_simple( union t_iterator *t, const unsigned char *input,
		     const struct ts_context *ctx );
void ts_sha2_L35_final_t_simple(unsigned char *output, union t_iterator *t,
		     const struct ts_context *ctx );

struct SHA256_CTX;
void ts_sha256_init_ctx( struct SHA256_CTX *sha_ctx,
		     struct ts_context *ctx );
void ts_sha2_L1_prehash( struct ts_context *ctx );

struct SHA512_CTX;
void ts_sha512_init_ctx( struct SHA512_CTX *sha_ctx,
		     struct ts_context *ctx );
void ts_sha2_L35_prehash( struct ts_context *ctx );
