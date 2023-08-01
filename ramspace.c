#include <stdio.h>
#include <stdlib.h>
#include "tiny_sphincs.h"
#include "get_space.h"

#define STR(x) #x
#define XSTR(x) STR(x)
int main(int argc, char **argv) {
    if (argc < 1) return EXIT_FAILURE;
    FILE *output = fopen( argv[1], "a" );
    if (!output) return EXIT_FAILURE;

    const struct ts_parameter_set *ps = &PARM_SET;

    fprintf( output, "%-25.25s", XSTR(PARM_SET) );

    fprintf( output, "%5d", (int)sizeof(struct ts_context) );

    unsigned keygen_space = get_keygen_space(ps);

    fprintf( output, "     %5u", keygen_space );

    unsigned sig_space = get_sig_space(ps);

    fprintf( output, "        %5u", sig_space );

    unsigned ver_space = get_ver_space(ps);

    if (ver_space == 0) {
        fprintf( output, "     *FAILED*" );
    } else {
        fprintf( output, "     %5u", ver_space );
    }

    fprintf( output, "\n" );

    fclose(output);

    return EXIT_SUCCESS;
}
