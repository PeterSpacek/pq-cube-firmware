#ifndef SAMPLE_H
#define SAMPLE_H

#include "../../../pq-crypto/crypto_kem/ntruhps4096821/crypto_sort_int32.h"
#include "../../../pq-crypto/crypto_kem/ntruhps4096821/params.h"
#include "../../../pq-crypto/crypto_kem/ntruhps4096821/poly.h"

void PQCLEAN_NTRUHPS4096821_CLEAN_sample_fg(poly *f, poly *g, const unsigned char uniformbytes[NTRU_SAMPLE_FG_BYTES]);
void PQCLEAN_NTRUHPS4096821_CLEAN_sample_rm(poly *r, poly *m, const unsigned char uniformbytes[NTRU_SAMPLE_RM_BYTES]);

void PQCLEAN_NTRUHPS4096821_CLEAN_sample_iid(poly *r, const unsigned char uniformbytes[NTRU_SAMPLE_IID_BYTES]);

void PQCLEAN_NTRUHPS4096821_CLEAN_sample_fixed_type(poly *r, const unsigned char uniformbytes[NTRU_SAMPLE_FT_BYTES]);


#endif
