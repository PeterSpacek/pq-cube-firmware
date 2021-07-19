#ifndef KYBER1024_M4_API_H
#define KYBER1024_M4_API_H

#include "kyber_params.h"

#define KYBER1024_M4_CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define KYBER1024_M4_CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define KYBER1024_M4_CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define KYBER1024_M4_CRYPTO_BYTES           KYBER_SSBYTES

#define KYBER1024_M4_CRYPTO_ALGNAME "Kyber1024"

int KYBER1024_M4_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int KYBER1024_M4_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int KYBER1024_M4_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
