#ifndef PQCLEAN_KYBER1024_CLEAN_CBD_H
#define PQCLEAN_KYBER1024_CLEAN_CBD_H
#include <stdint.h>
#include "../../../pq-crypto/crypto_kem/kyber1024/params.h"
#include "../../../pq-crypto/crypto_kem/kyber1024/poly.h"

void PQCLEAN_KYBER1024_CLEAN_poly_cbd_eta1(poly *r, const uint8_t buf[KYBER_ETA1 * KYBER_N / 4]);

void PQCLEAN_KYBER1024_CLEAN_poly_cbd_eta2(poly *r, const uint8_t buf[KYBER_ETA2 * KYBER_N / 4]);

#endif
