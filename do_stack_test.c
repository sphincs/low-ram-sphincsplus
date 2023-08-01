#include "do_stack_test.h"
extern "C" {
#include "tiny_sphincs.h"
}
#include <stdio.h>
#include "stack.h" /* DEBUG HACK */

static unsigned char private_key[128];

void do_stack_test(const struct ts_parameter_set *ps) {
    for (int i=0; i<128; i++) private_key[i] = i;

    struct ts_context ctx;
//    printf( "Context size = %u\n", (unsigned)sizeof ctx );


// init_stack();
printf( "About to ts_init_sign\n" ); /* DEBUG HACK */
    ts_init_sign( &ctx,
		  "Foo", 3,
                  ps,
                  private_key,
		  0 );
// unsigned z = measure_stack();
// printf( "Init size = %u\n", z );

//    unsigned biggest[6] = { 0 };
    for (;;) {
	unsigned char c[4];
// init_stack();
// int state = ctx.state;
	if (4 != ts_sign( c, 4, &ctx )) break;
// unsigned z2 = measure_stack();
// if (z2 > biggest[state]) biggest[state] = z2;
    }
printf( "Completed ts_sign\n" ); /* DEBUG HACK */
// for (int i=0; i<6; i++) printf( "%d: %u\n", i, biggest[i] );
}

static int random_func(unsigned char *p, size_t n) {
    for (size_t i=0; i<n; i++) {
	p[i] = i+1;
    }
    return 1;
}

void do_stack_test_keygen(const struct ts_parameter_set *ps) {
    static unsigned char private_key[4*32];

    (void)ts_gen_key( private_key, 0, ps, random_func );
}
