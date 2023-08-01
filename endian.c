#include "endian.h"

unsigned long long bytes_to_ull(const unsigned char *p, unsigned n ) {
    unsigned long long res = 0;
    for (unsigned i=0; i<n; i++) {
	res = 256*res + p[i];
    }
    return res;
}

void ull_to_bytes(unsigned char *p, unsigned long long val, unsigned n) {
    for (unsigned i=n; i>0; i--) {
	p[i-1] = val & 0xff;
	val >>= 8;
    }
}

void u32_to_bytes(unsigned char *p, uint32_t val) {
    ull_to_bytes(p, val, 4);
}
