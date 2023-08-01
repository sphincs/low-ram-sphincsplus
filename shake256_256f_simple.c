#include "internal.h"
#include "shake256_func.h"
#include "tune.h"

#if TS_SUPPORT_SHAKE && TS_SUPPORT_L5

const struct ts_parameter_set ts_ps_shake_256f_simple = {
    32,                /* Size of the hash */
    35,                /* # of FORS trees */
    9,                 /* Height of each FORS tree */
    68,                /* Hypertree height */
    17,                /* # of levels of Merkle trees */
    4,                 /* Height of each Merkle tree = h/d */
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
