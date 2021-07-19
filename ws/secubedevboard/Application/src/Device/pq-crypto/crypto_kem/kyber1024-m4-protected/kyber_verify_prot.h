#ifndef kyber_VERIFY_prot_H
#define kyber_VERIFY_prot_H

#include <stdio.h>

unsigned char kyber_verify_prot(const unsigned char *a, const unsigned char *b, size_t len);

void kyber_cmov_prot(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);

#endif
