#include "internal.h"

/*
 * These functions return the sizes of various public objects
 * (the 'private key' is a public object?  Well, yes, to this implementation.
 * as we expect the caller to handle it directly)
 */

unsigned ts_size_private_key( const struct ts_parameter_set *ps ) {
    return 4 * ps->n;
}

unsigned ts_size_public_key( const struct ts_parameter_set *ps ) {
    return 2 * ps->n;
}
unsigned ts_size_signature( const struct ts_parameter_set *ps ) {
    return ps->n * (1 +                           /* R */
		   (ps->t + 1) * ps->k +          /* FORS trees */
		   ps->d * (2*ps->n+3) +          /* WOTS+ signatures */
                   ps->h);                        /* Merkle trees */
}
