#ifndef ntru_VERIFY_H
#define ntru_VERIFY_H

#include <stdio.h>

/* returns 0 for equal strings, 1 for non-equal strings */
unsigned char ntru_verify(const unsigned char *a, const unsigned char *b, size_t len);

/* b = 1 means mov, b = 0 means don't mov*/
void ntru_cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);

#endif
