#ifndef CBD_H
#define CBD_H
/*---------------------------------------------------------------------
This file has been adapted from the implementation
(available at, Public Domain https://github.com/pq-crystals/kyber)
of "CRYSTALS – Kyber: a CCA-secure module-lattice-based KEM"
by : Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint,
Vadim Lyubashevsky, John M. Schanck, Peter Schwabe & Damien stehle
----------------------------------------------------------------------*/
#include <stdint.h>
#include "../../../pq-crypto/crypto_kem/firesaber/SABER_params.h"

void PQCLEAN_FIRESABER_CLEAN_cbd(uint16_t s[SABER_N], const uint8_t buf[SABER_POLYCOINBYTES]);


#endif
