#ifndef PQCLEAN_KYBER1024_CLEAN_VERIFY_H
#define PQCLEAN_KYBER1024_CLEAN_VERIFY_H
#include <stddef.h>
#include <stdint.h>
#include "../../../pq-crypto/crypto_kem/kyber1024/params.h"

int PQCLEAN_KYBER1024_CLEAN_verify(const uint8_t *a, const uint8_t *b, size_t len);

void PQCLEAN_KYBER1024_CLEAN_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

#endif
