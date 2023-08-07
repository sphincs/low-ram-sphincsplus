#include "internal.h"
#include "sha2_func.h"
#include "tune.h"

#if TS_SUPPORT_SHA2 && TS_SUPPORT_L5 && TS_SUPPORT_S

const struct ts_parameter_set ts_ps_sha2_256s_simple = {
    32,                /* Size of the hash */
    22,                /* # of FORS trees */
    14,                /* Height of each FORS tree */
    64,                /* Hypertree height */
    8,                 /* # of levels of Merkle trees */
    8,                 /* Height of each Merkle tree = h/d */
    1,                 /* This is a SHA-2 parameter set */

    ts_sha2_L35_prf_msg, /* prf_msg */
    ts_sha2_L35_hash_msg, /* hash_msg */
    ts_sha2_prf,     /* prf */
    ts_sha2_f_simple, /* f */
    ts_sha2_L35_init_t_simple,  /* init_t */
    ts_sha2_L35_next_t_simple,  /* next_t */
    ts_sha2_L35_final_t_simple, /* final_t */
#if TS_SHA2_OPTIMIZATION
    ts_sha2_L35_prehash, /* compute_prehash */
#else
    0,                  /* compute_prehash */
#endif
};

#endif
