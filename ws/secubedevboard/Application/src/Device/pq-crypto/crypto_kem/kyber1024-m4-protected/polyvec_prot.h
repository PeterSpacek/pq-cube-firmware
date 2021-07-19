#ifndef POLYVEC_prot_H
#define POLYVEC_prot_H

#include "kyber_params_prot.h"
#include "kyber_poly_prot.h"

typedef struct {
    poly vec[KYBER_K];
} polyvec;

void polyvec_compress(unsigned char *r, polyvec *a);
void polyvec_decompress(polyvec *r, const unsigned char *a);

void polyvec_tobytes(unsigned char *r, polyvec *a);
void polyvec_frombytes(polyvec *r, const unsigned char *a);

void polyvec_ntt(polyvec *r, int protection);
void polyvec_invntt(polyvec *r, int protection);

void polyvec_reduce(polyvec *r);

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
