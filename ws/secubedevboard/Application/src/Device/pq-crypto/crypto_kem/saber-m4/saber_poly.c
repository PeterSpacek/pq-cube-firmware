/*---------------------------------------------------------------------
This file has been adapted from the implementation 
(available at, Public Domain https://github.com/pq-crystals/kyber) 
of "CRYSTALS – Kyber: a CCA-secure module-lattice-based KEM"
by : Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint, 
Vadim Lyubashevsky, John M. Schanck, Peter Schwabe & Damien stehle
----------------------------------------------------------------------*/
#include "saber_cbd.h"
#include "saber_poly.h"
#include <stdio.h>

#include "../../../pq-crypto/common/fips202.h"
#include "saber_m4_api.h"



void GenSecret(uint16_t r[SABER_K][SABER_N],const unsigned char *seed){


		uint32_t i;

		uint8_t buf[SABER_NOISEBUFSIZE];//SABER_MU*SABER_N*SABER_K/8

		shake128(buf, SABER_NOISEBUFSIZE, seed,SABER_NOISESEEDBYTES);

		for(i=0;i<SABER_K;i++)
		{
			saber_cbd(r[i],buf+i*SABER_MU*SABER_N/8);
		}
}
