#if !defined(ENDIAN_H_)
#define ENDIAN_H_

#include <stdint.h>

/*
 * Return the value of the n bytes at location p, interpreted as a bigendian
 * unsigned integer
 */
unsigned long long ts_bytes_to_ull(const unsigned char *p, unsigned n );

/*
 * Set the n bytes at location p to the value 'val', encoding it as a
 * bigendian unsigned integer
 */
void ts_ull_to_bytes(unsigned char *p, unsigned long long val, unsigned n);

#endif /* ENDIAN_H_ */
