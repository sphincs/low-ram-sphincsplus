/*
 * This is the top level code for the utility that checks for RAM usage
 * This is meant to be compiled and run by the ramspace.py script
 * It probably doesn't make a whole lot of sense in any other context
 */

#include <stdio.h>
#include <stdlib.h>
#include "tiny_sphincs.h"
#include "get_space.h"

#define STR(x) #x
#define XSTR(x) STR(x)
int main(int argc, char **argv) {
    if (argc < 1) return EXIT_FAILURE;

        /* argv[1] is the name of the file (ramspace.out) we're storing */
        /* our findings in.  Append to it */
    FILE *output = fopen( argv[1], "a" );
    if (!output) return EXIT_FAILURE;

    const struct ts_parameter_set *ps = &PARM_SET;

        /* State the parameter set we're testing */
    fprintf( output, "%-25.25s", XSTR(PARM_SET) );

        /* State the size of the context */
    fprintf( output, "%5d", (int)sizeof(struct ts_context) );

        /* State the RAM used during key generation */
    unsigned keygen_space = get_keygen_space(ps);
    fprintf( output, "     %5u", keygen_space );

        /* State the space used during signature generation */
    unsigned sig_space = get_sig_space(ps);
    fprintf( output, "        %5u", sig_space );

        /* State the space used during signature verification */
    unsigned ver_space = get_ver_space(ps);
    if (ver_space == 0) {
        fprintf( output, "     *FAILED*" );
    } else {
        fprintf( output, "     %5u", ver_space );
    }

        /* And we're done... */
    fprintf( output, "\n" );
    fclose(output);

    return EXIT_SUCCESS;
}
