#include "internal.h"
#include "shake256_func.h"
#include "tune.h"

#if TS_SUPPORT_SHAKE

const struct ts_parameter_set ts_ps_shake_128f_simple = {
    16,                /* Size of the hash */
    33,                /* # of FORS trees */
    6,                 /* Height of each FORS tree */
    66,                /* Hypertree height */
    22,                /* # of levels of Merkle trees */
    3,                 /* Height of each Merkle tree = h/d */
    0,                 /* This is not a SHA-2 parameter set */

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
