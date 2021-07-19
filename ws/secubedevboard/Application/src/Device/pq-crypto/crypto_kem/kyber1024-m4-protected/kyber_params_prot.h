#ifndef kyber_PARAMS_prot_H
#define kyber_PARAMS_prot_H

#define KYBER_K 4 /* Change this for different security strengths */

/* Don't change parameters below this line */

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_ETA 2

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES              384
#define KYBER_POLYVECBYTES           (KYBER_K * KYBER_POLYBYTES)

#define KYBER_POLYCOMPRESSEDBYTES    160
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 352)

#define KYBER_INDCPA_MSGBYTES       KYBER_SYMBYTES
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES +  KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES) /* 32 bytes of additional space to save H(pk) */
#define KYBER_CIPHERTEXTBYTES  KYBER_INDCPA_BYTES

#endif
