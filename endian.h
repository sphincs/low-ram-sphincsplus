#if !defined(ENDIAN_H_)
#define ENDIAN_H_

#include <stdint.h>

unsigned long long bytes_to_ull(const unsigned char *p, unsigned n );
void ull_to_bytes(unsigned char *p, unsigned long long val, unsigned n);
void u32_to_bytes(unsigned char *p, uint32_t val);

#endif /* ENDIAN_H_ */
