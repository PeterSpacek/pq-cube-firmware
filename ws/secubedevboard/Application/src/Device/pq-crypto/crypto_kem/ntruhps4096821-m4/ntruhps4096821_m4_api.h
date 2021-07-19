#ifndef NTRUHPS4096821_M4_API_H
#define NTRUHPS4096821_M4_API_H

#include <stdint.h>

#define NTRUHPS4096821_M4_CRYPTO_SECRETKEYBYTES 1590
#define NTRUHPS4096821_M4_CRYPTO_PUBLICKEYBYTES 1230
#define NTRUHPS4096821_M4_CRYPTO_CIPHERTEXTBYTES 1230
#define NTRUHPS4096821_M4_CRYPTO_BYTES 32

#define NTRUHPS4096821_M4_CRYPTO_ALGNAME "NTRU-HPS4096821"

int NTRUHPS4096821_M4_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

int NTRUHPS4096821_M4_crypto_kem_enc(uint8_t *c, uint8_t *k, const uint8_t *pk);

int NTRUHPS4096821_M4_crypto_kem_dec(uint8_t *k, const uint8_t *c, const uint8_t *sk);

#endif
