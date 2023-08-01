#include "internal.h"
#include "sha2_func.h"
#include "tune.h"

#if TS_SUPPORT_SHA2 && TS_SUPPORT_S

const struct ts_parameter_set ts_ps_sha2_128s_simple = {
    16,                /* Size of the hash */
    14,                /* # of FORS trees */
    12,                /* Height of each FORS tree */
    63,                /* Hypertree height */
    7,                 /* # of levels of Merkle trees */
    9,                 /* Height of each Merkle tree = h/d */
    1,                 /* This is a SHA-256 parameter set */

    ts_sha2_L1_prf_msg, /* prf_msg */
    ts_sha2_L1_hash_msg, /* hash_msg */
    ts_sha2_prf,     /* prf */
    ts_sha2_f_simple, /* f */
    ts_sha2_L1_init_t_simple,  /* init_t */
    ts_sha2_L1_next_t_simple,  /* next_t */
    ts_sha2_L1_final_t_simple, /* final_t */
#if TS_SHA2_OPTIMIZATION
    ts_sha2_L1_prehash, /* compute_prehash */
#else
    0,                  /* compute_prehash */
#endif
};

#endif
