#include "internal.h"
#include "shake256_func.h"
#include "tune.h"

#if TS_SUPPORT_SHAKE && TS_SUPPORT_S && TS_SUPPORT_L5

const struct ts_parameter_set ts_ps_shake_256s_simple = {
    32,                /* Size of the hash */
    22,                /* # of FORS trees */
    14,                /* Height of each FORS tree */
    64,                /* Hypertree height */
    8,                 /* # of levels of Merkle trees */
    8,                 /* Height of each Merkle tree = h/d */
    0,                 /* This is not a SHA-256 parameter set */

    ts_shake256_prf_msg, /* prf_msg */
    ts_shake256_hash_msg, /* hash_msg */
    ts_shake256_prf,     /* prf */
    ts_shake256_f_simple, /* f */
    ts_shake256_init_t_simple,  /* init_t */
    ts_shake256_next_t_simple,  /* next_t */
    ts_shake256_final_t_simple, /* final_t */
    0,                 /* compute_prehash */
};

#endif
