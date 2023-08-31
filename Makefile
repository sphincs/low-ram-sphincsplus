CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -fomit-frame-pointer -Os
NO_OPT_CFLAGS = -Wall -Wextra -Wpedantic -fomit-frame-pointer

# If ALL_PARM_SETS is defined, override tune.h to allow all parameter sets
ifeq ($(ALL_PARM_SETS),1)
DFLAGS += -DTUNE_H_ -DTS_SUPPORT_L5=1 -DTS_SUPPORT_SHAKE=1 \
	  -DTS_SUPPORT_SHA2=1 -DTS_SUPPORT_S=1 \
	  -DTS_SHA2_OPTIMIZATION=1
endif

.PHONY: clean

%.o : %.c ; $(CC) -c $(CFLAGS) $(DFLAGS) $< -o $@

OBJECTS = tiny_sphincs.o key_gen.o size.o \
	  verify.o \
	  fips202.o shake256_hash.o shake256_simple.o \
	  sha256.o sha256_hash.o sha2_simple.o sha256_L1_hash.o \
	  sha512.o sha512_hash.o \
	  sha256_L1_hash_simple.o \
	  sha512_L35_hash_simple.o \
	  endian.o \
	  shake256_128f_simple.o shake256_128s_simple.o \
	  shake256_192f_simple.o shake256_192s_simple.o \
	  shake256_256f_simple.o shake256_256s_simple.o \
	  sha2_128f_simple.o sha2_128s_simple.o \
	  sha2_192f_simple.o sha2_192s_simple.o \
	  sha2_256f_simple.o sha2_256s_simple.o

TEST_SOURCES = test_sphincs.c test_testvector.c test_sha512.c test_shake.c \
	       test_verify.c

#
# Makes the regression test executable
test_sphincs: $(TEST_SOURCES) $(OBJECTS)
	$(CC) $(CFLAGS) $(DFLAGS) -o $@ $(TEST_SOURCES) $(OBJECTS)

clean:
	-$(RM) $(OBJECTS)
	-$(RM) ramspace

#
# Internal rule used by the ./ramspace.py script to find the amount of RAM
# used by the parameter set specified by $(PARM_SET).
# This shouldn't be called manually; instead, run the ./ramspace.py script
ramspace: ramspace.c get_space.c get_space2.c stack.c $(OBJECTS)
	$(CC) -o $@ $(NO_OPT_CFLAGS) $(DFLAGS) -DPARM_SET=$(PARM_SET) ramspace.c get_space.c get_space2.c stack.c $(OBJECTS)
	./ramspace $(OUTPUT_FILE)
