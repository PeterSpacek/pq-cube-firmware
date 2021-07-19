#ifndef VERIFY_H
#define VERIFY_H

#include <stddef.h>
#include "../../../pq-crypto/crypto_kem/ntruhps4096821/params.h"

void PQCLEAN_NTRUHPS4096821_CLEAN_cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);

#endif
