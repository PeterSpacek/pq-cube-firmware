#ifndef PQCLEAN_KYBER1024_CLEAN_REDUCE_H
#define PQCLEAN_KYBER1024_CLEAN_REDUCE_H
#include <stdint.h>
#include "../../../pq-crypto/crypto_kem/kyber1024/params.h"

#define MONT 2285 // 2^16 mod q
#define QINV 62209 // q^-1 mod 2^16

int16_t PQCLEAN_KYBER1024_CLEAN_montgomery_reduce(int32_t a);

int16_t PQCLEAN_KYBER1024_CLEAN_barrett_reduce(int16_t a);

#endif