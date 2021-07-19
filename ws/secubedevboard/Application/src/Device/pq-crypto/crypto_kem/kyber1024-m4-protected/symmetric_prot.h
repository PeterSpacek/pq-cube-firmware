#ifndef SYMMETRIC_prot_H
#define SYMMETRIC_prot_H

#include "../../common/fips202.h"
#include "kyber_params_prot.h"
#include <stddef.h>

void kyber_shake128_absorb_prot(shake128ctx *s, const unsigned char *input, unsigned char x, unsigned char y);
void kyber_shake128_squeezeblocks_prot(unsigned char *output, size_t nblocks, shake128ctx *s);
void shake256_prf_prot(unsigned char *output, size_t outlen, const unsigned char *key, unsigned char nonce);

#define hash_h_prot(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g_prot(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb_prot(STATE, IN, X, Y) kyber_shake128_absorb_prot(STATE, IN, X, Y)
#define xof_squeezeblocks_prot(OUT, OUTBLOCKS, STATE) kyber_shake128_squeezeblocks_prot(OUT, OUTBLOCKS, STATE)
#define prf_prot(OUT, OUTBYTES, KEY, NONCE) shake256_prf_prot(OUT, OUTBYTES, KEY, NONCE)
#define kdf_prot(OUT, IN, INBYTES) shake256(OUT, KYBER_SSBYTES, IN, INBYTES)

#define XOF_BLOCKBYTES 168

typedef shake128ctx xof_state;

#endif /* SYMMETRIC_H */
