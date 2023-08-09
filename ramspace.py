#! /usr/bin/env python3
#
# This is a script that lists the amount of RAM used by tiny sphincs
# For each of the supported parameter sets, it compiles a minimal version
# of tiny sphincs that supports that parameter set, and then runs a utility
# that probes the RAM usage (for the key generation, signature generation
# and signature verification) operations
# It places all these into the ramspace.out file
#
# It uses the 'small-and-slow' implementationss of both the SHA2 and SHAKE
# parameter sets.  Both these options slow down sphincs+ a lot, while saving
# a relatively small amount of RAM space; the point of this file is to show
# how little RAM we can use, and so that's what we do.  In practice, we're
# likely to select the 'use-a-bit-more-ram/go-a-lot-faster' option

import fileinput
import itertools
import os
import sys
from subprocess import DEVNULL, run

hashes = ["sha2", "shake"]
options = ["f", "s"]
sizes = [128, 192, 256]

if os.path.exists("ramspace.out"):
    os.remove("ramspace.out")
file1 = open("ramspace.out", "a" );
file1.write( "This file lists the amount of RAM used by the tiny sphincs package\n" );
file1.write( "\n" );
file1.write( "Parameter Set           CTX size  Keygen size  Sig size  Ver size\n" );
file1.close()

for hash in hashes:
    for size in sizes:
        for speed in options:
            # Defining TUNE_H_ effectively disables the existing tune.h file, and
            # allows us to plug in our own settings
            # TS_SHA2_OPTIONIZATION=0, TS_SHAKE256_OPT=2 are the 'small-and-slow'
            # options for SHA2 and SHAKE256
            DFLAGS = "-DTUNE_H_ -DTS_SHA2_OPTIMIZATION=0"
            DFLAGS = DFLAGS + " -DTS_SHAKE256_OPT=2"

            # Enable the parameter set we're testing
            if size == 256:
                DFLAGS = DFLAGS + " -DTS_SUPPORT_L5=1 -DTS_SUPPORT_L3=1"
            elif size == 192:
                DFLAGS = DFLAGS + " -DTS_SUPPORT_L3=1 -DTS_SUPPORT_L5=0"
            else:
                DFLAGS = DFLAGS + " -DTS_SUPPORT_L3=0 -DTS_SUPPORT_L5=0"
            if hash == "sha2":
                DFLAGS = DFLAGS + " -DTS_SUPPORT_SHA2=1 -DTS_SUPPORT_SHAKE=0"
            else:
                DFLAGS = DFLAGS + " -DTS_SUPPORT_SHAKE=1 -DTS_SUPPORT_SHA2=0"
            if speed == "s":
                DFLAGS = DFLAGS + " -DTS_SUPPORT_S=1"
            else:
                DFLAGS = DFLAGS + " -DTS_SUPPORT_S=0"

            # And this is the name of the parameter set
            PARM_SET = 'ts_ps_{}_{}{}_simple'.format(hash, size, speed)

            # Make sure we're running from a clean slate
            run(["make", "clean"], stdout=DEVNULL, stderr=sys.stderr)

            # Compile the package and run the utility that'll generate the
            # line summarizing this parameter set into the ramspace.out file
            run(["make", "ramspace", 'DFLAGS={}'.format(DFLAGS),
                                     'PARM_SET={}'.format(PARM_SET),
                                     'OUTPUT_FILE=ramspace.out'],
                                     stdout=sys.stdout, stderr=sys.stderr)

            # We've compiled a version of the utility that doesn't correspond to
            # tune.h - make sure we don't leave anything to trip over
            run(["make", "clean"], stdout=DEVNULL, stderr=sys.stderr)

# And append the explanatory legend at the end
file1 = open("ramspace.out", "a" );
file1.write( "\n" );
file1.write( "Legend:\n" );
file1.write( "Parameter Set - the Sphincs+ parameter set being tested.  Each test used a minimal tune.h to enable the named parameter set\n" );
file1.write( "CTX size - the size of the ts_context structure used to track Sphincs+ state while streaming.  This is included in the RAM usage for Sig size and Ver size\n" );
file1.write( "Keygen size - the amount of RAM used for key generation\n" );
file1.write( "Sig size - the amount of RAM used for signature generation\n" );
file1.write( "Ver size - the amount of RAM used for signature verification\n" );
file1.close()
