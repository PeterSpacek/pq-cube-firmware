#ifndef kyber_POLY_prot_H
#define kyber_POLY_prot_H

#include "kyber_params_prot.h"
#include <stdint.h>

#define poly_getnoise_prot(p, seed, nonce) poly_noise_prot(p, seed, nonce, 0)
#define poly_addnoise_prot(p, seed, nonce) poly_noise_prot(p, seed, nonce, 1)

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
    int16_t coeffs[KYBER_N];
} poly;

void poly_compress_prot(unsigned char *r, poly *a);
void poly_decompress_prot(poly *r, const unsigned char *a);

void poly_packcompress_prot(unsigned char *r, poly *a, int i);
void poly_unpackdecompress_prot(poly *r, const unsigned char *a, int i);

int cmp_poly_compress_prot(const unsigned char *r, poly *a);
int cmp_poly_packcompress_prot(const unsigned char *r, poly *a, int i);

void poly_tobytes_prot(unsigned char *r, poly *a);
void poly_frombytes_prot(poly *r, const unsigned char *a);
void poly_frombytes_mul_prot(poly *r, const unsigned char *a);

void poly_frommsg_prot(poly *r, const unsigned char msg[KYBER_SYMBYTES]);
void poly_tomsg_prot(unsigned char msg[KYBER_SYMBYTES], poly *a);

void poly_noise_prot(poly *r, const unsigned char *seed, unsigned char nonce, int add);

void poly_ntt_prot(poly *r, int protection);
void poly_invntt_prot(poly *r, int protection);
void poly_basemul_prot(poly *r, const poly *a, const poly *b);
void poly_basemul_acc_prot(poly *r, const poly *a, const poly *b);
void poly_frommont_prot(poly *r);

void poly_reduce_prot(poly *r);

void poly_add_prot(poly *r, const poly *a, const poly *b);
void poly_sub_prot(poly *r, const poly *a, const poly *b);

void poly_zeroize_prot(poly *p);

#endif
