#if !defined( TUNE_H_ )
#define TUNE_H_

/*
 * This file is here to allow tweaks by the user; it is meant to be
 * adjusted by the user to target their needs.
 *
 * The package tries to minimize the amount of RAM used, however we can
 * reduce it further by not supporting certain options.  This file is
 * here to assume such tweaking.
 *
 * Some parameter sets require more memory to run (and since we never
 * dynamically allocate memory, the memory we use depends on the worst
 * parameter set we support).
 * This file allows the user to specify which parameter sets, so we don't
 * have to spend space for cases we won't need)
 *
 * Note that some options don't use extra memory; we don't bother
 * disabling those from this file
 */

#define TS_SUPPORT_SHAKE 1 /* We support SHAKE parameter sets */
#define TS_SUPPORT_SHA2  1 /* We support SHA2 parameter sets */
/* Haraka always uses lots of RAM, hence we just never support it */
/* Now, you can support both SHAKE and SHA2, if you want */

#define TS_SUPPORT_L5 1 /* We support L5 (and L3 and L1) parameter sets */
#define TS_SUPPORT_L3 0 /* We support L3 (and L1) parameter sets */
/* We always support L1 parameter sets, hence we don't need a #define */

#define TS_SUPPORT_S 1 /* We support S parameter sets */
/* We always support F parameter sets */


/*
 * This doesn't actually define which parameter sets we can use; instead it
 * defines whether we do a specific optimization for SHA-2 parameter sets
 * Benefit: it approximately halves the signing time
 * Cost: a bit more memory (32 bytes for L1, 96 for L3/L5)
 * Note that you pay for this for SHAKE parameter sets as well (if you
 * support both), even though it doesn't speed SHAKE parameter set at all)
 */
#define TS_SHA2_OPTIMIZATION 1

/*
 * This also doesn't actually define which parameter sets we can use; instead
 * it defines which of three different approaches to implementing SHAKE-256
 * All are valid (that is, the signatures are generated/verified correctly);
 * however they have different practical implications.  Below are the options:
 * 0 uses a relatively high performance Keccak implementation; it uses quite
 *     a bit of RAM (stack space)
 * 1 is an attempt to tweak the code to try to reduce the amount of stack
 *     space (while maintaining most of the performance).  On my CPU/compiler,
 *     it actually uses 8 bytes more RAM (I blame the optimizer in my
 *     compiler); however it may work out better on yours
 * 2 is a completely different Keccak implementation which uses far less
 *     RAM (about 180 btes less).  On the other hand, it is considerably slower
 *     (perhaps a factor of 10)
 *
 * This setting has no effect on SHA2 parameter sets
 */
#define TS_SHAKE256_OPT 0

/* Sanity check */
#if !TS_SUPPORT_SHAKE && !TS_SUPPORT_SHA2
#error We need to support some hash function (either SHAKE or SHA2 or both)
#endif

#endif /* TUNE_H_ */
