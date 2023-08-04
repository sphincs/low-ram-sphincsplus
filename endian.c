#include "endian.h"

/*
 * Return the value of the n bytes at location p, interpreted as a bigendian
 * unsigned integer
 */
unsigned long long ts_bytes_to_ull(const unsigned char *p, unsigned n ) {
    unsigned long long res = 0;
    for (unsigned i=0; i<n; i++) {
	res = 256*res + p[i];
    }
    return res;
}

/*
 * Set the n bytes at location p to the value 'val', encoding it as a
 * bigendian unsigned integer
 */
void ts_ull_to_bytes(unsigned char *p, unsigned long long val, unsigned n) {
    for (unsigned i=n; i>0; i--) {
	p[i-1] = val & 0xff;
	val >>= 8;
    }
}
