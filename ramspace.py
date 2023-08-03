#! /usr/bin/env python3
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
            DFLAGS = "-DTUNE_H_ -DTS_SHA2_OPTIMIZATION=0"
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
            PARM_SET = 'ts_ps_{}_{}{}_simple'.format(hash, size, speed)

            run(["make", "clean"], stdout=DEVNULL, stderr=sys.stderr)

            run(["make", "ramspace", 'DFLAGS={}'.format(DFLAGS),
                                     'PARM_SET={}'.format(PARM_SET),
                                     'OUTPUT_FILE=ramspace.out'],
                                     stdout=sys.stdout, stderr=sys.stderr)

            run(["make", "clean"], stdout=DEVNULL, stderr=sys.stderr)

file1 = open("ramspace.out", "a" );
file1.write( "\n" );
file1.write( "Legend:\n" );
file1.write( "Parameter Set - the Sphincs+ parameter set being tested.  Each test used a minimal tune.h to enable the named parameter set\n" );
file1.write( "CTX size - the size of the ts_context structure used to track Sphincs+ state while streaming.  This is included in the RAM usage for Sig size and Ver size\n" );
file1.write( "Keygen size - the amount of RAM used for key generation\n" );
file1.write( "Sig size - the amount of RAM used for signature generation\n" );
file1.write( "Ver size - the amount of RAM used for signature verification\n" );
file1.close()
