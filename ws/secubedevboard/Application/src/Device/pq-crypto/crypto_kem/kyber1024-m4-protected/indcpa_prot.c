#include "indcpa_prot.h"
#include "ntt_prot.h"
#include "kyber_poly_prot.h"
#include "polyvec_prot.h"
#include "../../common/randombytes.h"
#include "symmetric_prot.h"

#include <string.h>
#include <stdint.h>

extern void doublebasemul_asm_acc_prot(int16_t *r, const int16_t *a, const int16_t *b, int16_t zeta);
/*************************************************
* Name:        matacc
*
* Description: Multiplies a row of A or A^T, generated on-the-fly,
*              with a vector of polynomials and accumulates into the result.
*
* Arguments:   - poly *r:                    pointer to output polynomial to accumulate in
*              - polyvec *b:                 pointer to input vector of polynomials to multiply with
*              - unsigned char i:            byte to indicate the index < KYBER_K of the row of A or A^T
*              - const unsigned char *seed:  pointer to the public seed used to generate A
*              - int transposed:             boolean indicatin whether A or A^T is generated
**************************************************/
static void matacc_prot(poly* r, polyvec *b, unsigned char i, const unsigned char *seed, int transposed) {
  unsigned char buf[XOF_BLOCKBYTES+1];
  xof_state state;
  int ctr, pos, k;
  uint16_t val;
  int16_t c[4];

  poly_zeroize_prot(r);

  for(int j=0;j<KYBER_K;j++) {
    ctr = pos = 0;
    if (transposed)
      xof_absorb_prot(&state, seed, i, j);
    else
      xof_absorb_prot(&state, seed, j, i);

    xof_squeezeblocks_prot(buf, 1, &state);

    while (ctr < KYBER_N/4)
    {
      k = 0;
      while(k < 4) {
        val = buf[pos] | ((uint16_t)buf[pos + 1] << 8);
        if (val < 19 * KYBER_Q) {
          val -= (val >> 12) * KYBER_Q; // Barrett reduction
          c[k++] = (int16_t) val;
        }

        pos += 2;
        if (pos + 2 > XOF_BLOCKBYTES) {
          xof_squeezeblocks_prot(buf, 1, &state);
          pos = 0;
        }
      }

      doublebasemul_asm_acc(&r->coeffs[4*ctr], &b->vec[j].coeffs[4*ctr], c, zetas_poly[ctr]);
      ctr++;
    }
  }
}

/*************************************************
* Name:        indcpa_keypair
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - unsigned char *pk: pointer to output public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
**************************************************/
void indcpa_keypair_prot(unsigned char *pk, unsigned char *sk)
{
    polyvec skpv;
    poly pkp;
    unsigned char buf[2 * KYBER_SYMBYTES];
    unsigned char *publicseed = buf;
    unsigned char *noiseseed = buf + KYBER_SYMBYTES;
    int i;
    unsigned char nonce = 0;

    randombytes(buf, KYBER_SYMBYTES);
    // for(i = 0; i<KYBER_SYMBYTES; i++)
    //   *(buf + i) = 0xAA;

    hash_g_prot(buf, buf, KYBER_SYMBYTES);

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_prot(skpv.vec + i, noiseseed, nonce++);

    // poly_ntt(&skpv.vec[0]);
    polyvec_ntt_prot(&skpv, 1);

    for (i = 0; i < KYBER_K; i++) {
        matacc_prot(&pkp, &skpv, i, publicseed, 0);
        poly_invntt_prot(&pkp, 1);

        poly_addnoise_prot(&pkp, noiseseed, nonce++);
        poly_ntt_prot(&pkp, 0);

        poly_tobytes_prot(pk+i*KYBER_POLYBYTES, &pkp);
    }

    polyvec_tobytes_prot(sk, &skpv);
    memcpy(pk + KYBER_POLYVECBYTES, publicseed, KYBER_SYMBYTES); // Pack the public seed in the public key
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *c:          pointer to output ciphertext (of length KYBER_INDCPA_BYTES bytes)
*              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
**************************************************/
void indcpa_enc_prot(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins) {
    polyvec sp;
    poly bp;
    poly *pkp = &bp;
    poly *k = &bp;
    poly *v = &sp.vec[0];
    const unsigned char *seed = pk+KYBER_POLYVECBYTES;
    int i;
    unsigned char nonce = 0;

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_prot(sp.vec + i, coins, nonce++);

    polyvec_ntt_prot(&sp, 1);

    for (i = 0; i < KYBER_K; i++) {
        matacc_prot(&bp, &sp, i, seed, 1);
        poly_invntt_prot(&bp, 1);

        poly_addnoise_prot(&bp, coins, nonce++);
        poly_reduce_prot(&bp);

        poly_packcompress_prot(c, &bp, i);
    }

    poly_frombytes_prot(pkp, pk);
    poly_basemul_prot(v, pkp, &sp.vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        poly_frombytes_prot(pkp, pk + i*KYBER_POLYBYTES);
        poly_basemul_acc_prot(v, pkp, &sp.vec[i]);
    }

    poly_invntt_prot(v, 1);

    poly_addnoise_prot(v, coins, nonce++);

    poly_frommsg_prot(k, m);
    poly_add_prot(v, v, k);
    poly_reduce_prot(v);

    poly_compress_prot(c + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/*************************************************
* Name:        indcpa_enc_cmp
*
* Description: Re-encryption function.
*              Compares the re-encypted ciphertext with the original ciphertext byte per byte.
*              The comparison is performed in a constant time manner.
*
*
* Arguments:   - unsigned char *ct:         pointer to input ciphertext to compare the new ciphertext with (of length KYBER_INDCPA_BYTES bytes)
*              - const unsigned char *m:    pointer to input message (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const unsigned char *pk:   pointer to input public key (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - const unsigned char *coin: pointer to input random coins used as seed (of length KYBER_SYMBYTES bytes)
*                                           to deterministically generate all randomness
* Returns:     - boolean byte indicating that re-encrypted ciphertext is NOT equal to the original ciphertext
**************************************************/
unsigned char indcpa_enc_cmp_prot(const unsigned char *c,
                             const unsigned char *m,
                             const unsigned char *pk,
                             const unsigned char *coins) {
    uint64_t rc = 0;
    polyvec sp;
    poly bp;
    poly *pkp = &bp;
    poly *k = &bp;
    poly *v = &sp.vec[0];
    const unsigned char *seed = pk+KYBER_POLYVECBYTES;
    int i;
    unsigned char nonce = 0;

    for (i = 0; i < KYBER_K; i++)
        poly_getnoise_prot(sp.vec + i, coins, nonce++);

    polyvec_ntt_prot(&sp, 1);

    for (i = 0; i < KYBER_K; i++) {
        matacc_prot(&bp, &sp, i, seed, 1);
        poly_invntt_prot(&bp, 1);

        poly_addnoise_prot(&bp, coins, nonce++);
        poly_reduce_prot(&bp);

        rc |= cmp_poly_packcompress_prot(c, &bp, i);
    }

    poly_frombytes_prot(pkp, pk);
    poly_basemul_prot(v, pkp, &sp.vec[0]);
    for (i = 1; i < KYBER_K; i++) {
        poly_frombytes_prot(pkp, pk + i*KYBER_POLYBYTES);
        poly_basemul_acc_prot(v, pkp, &sp.vec[i]);
    }

    poly_invntt_prot(v, 1);

    poly_addnoise_prot(v, coins, nonce++);
    poly_frommsg_prot(k, m);
    poly_add_prot(v, v, k);
    poly_reduce_prot(v);

    rc |= cmp_poly_compress_prot(c + KYBER_POLYVECCOMPRESSEDBYTES, v);

    rc = ~rc + 1;
    rc >>= 63;
    return (unsigned char)rc;
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - unsigned char *m:        pointer to output decrypted message (of length KYBER_INDCPA_MSGBYTES)
*              - const unsigned char *c:  pointer to input ciphertext (of length KYBER_INDCPA_BYTES)
*              - const unsigned char *sk: pointer to input secret key (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void __attribute__ ((noinline)) indcpa_dec_prot(unsigned char *m,
                                           const unsigned char *c,
                                           const unsigned char *sk)
 {
    poly mp, bp;
    poly *v = &bp;

    poly_unpackdecompress_prot(&mp, c, 0);
    poly_ntt_prot(&mp, 0);
    poly_frombytes_mul_prot(&mp, sk);
    for(int i = 1; i < KYBER_K; i++)
    {
        poly_unpackdecompress_prot(&bp, c, i);
        poly_ntt_prot(&bp, 0);
        poly_frombytes_mul_prot(&bp, sk + i*KYBER_POLYBYTES);
        poly_add_prot(&mp, &mp, &bp);
    }

    poly_invntt_prot(&mp, 1);
    poly_decompress_prot(v, c+KYBER_POLYVECCOMPRESSEDBYTES);
    poly_sub_prot(&mp, v, &mp);
    poly_reduce_prot(&mp);

    poly_tomsg_prot(m, &mp);
}
