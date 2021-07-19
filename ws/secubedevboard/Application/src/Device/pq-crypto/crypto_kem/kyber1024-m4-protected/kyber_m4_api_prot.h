#ifndef KYBER1024_M4_API_prot_H
#define KYBER1024_M4_API_prot_H

#include "kyber_params_prot.h"

#define KYBER1024_M4_CRYPTO_SECRETKEYBYTES_prot  KYBER_SECRETKEYBYTES
#define KYBER1024_M4_CRYPTO_PUBLICKEYBYTES_prot  KYBER_PUBLICKEYBYTES
#define KYBER1024_M4_CRYPTO_CIPHERTEXTBYTES_prot KYBER_CIPHERTEXTBYTES
#define KYBER1024_M4_CRYPTO_BYTES_prot           KYBER_SSBYTES

#define KYBER1024_M4_CRYPTO_ALGNAME_prot "Kyber1024"

int KYBER1024_M4_crypto_kem_keypair_prot(unsigned char *pk, unsigned char *sk);

int KYBER1024_M4_crypto_kem_enc_prot(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int KYBER1024_M4_crypto_kem_dec_prot(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
