#include "ntru_poly.h"
#include "../../../pq-crypto/crypto_kem/ntruhps4096821-m4/owcpa.h"

#include "../../../pq-crypto/crypto_kem/ntruhps4096821-m4/sample.h"

static int owcpa_check_ciphertext(const unsigned char *ciphertext) {
    /* A ciphertext is log2(q)*(n-1) bits packed into bytes.  */
    /* Check that any unused bits of the final byte are zero. */

    uint16_t t = 0;

    t = ciphertext[NTRU_CIPHERTEXTBYTES - 1];
    t &= 0xff << (8 - (7 & (NTRU_LOGQ * NTRU_PACK_DEG)));

    /* We have 0 <= t < 256 */
    /* Return 0 on success (t=0), 1 on failure */
    return (int) (1 & ((~t + 1) >> 15));
}

static int owcpa_check_r(const poly *r) {
    /* Check that r is in message space. */
    /* Note: Assumes that r has coefficients in {0, 1, ..., q-1} */
    int i;
    uint64_t t = 0;
    uint16_t c;
    for (i = 0; i < NTRU_N; i++) {
        c = MODQ(r->coeffs[i] + 1);
        t |= c & (NTRU_Q - 4); /* 0 if c is in {0,1,2,3} */
        t |= (c + 1) & 0x4;   /* 0 if c is in {0,1,2} */
    }
    t |= r->coeffs[NTRU_N - 1]; /* Coefficient n-1 must be zero */
    t = (~t + 1); // two's complement
    t >>= 63;
    return (int) t;
}

static int owcpa_check_m(const poly *m) {
    /* Check that m is in message space. */
    /* Note: Assumes that m has coefficients in {0,1,2}. */
    int i;
    uint64_t t = 0;
    uint16_t p1 = 0;
    uint16_t m1 = 0;
    for (i = 0; i < NTRU_N; i++) {
        p1 += m->coeffs[i] & 0x01;
        m1 += (m->coeffs[i] & 0x02) >> 1;
    }
    /* Need p1 = m1 and p1 + m1 = NTRU_WEIGHT */
    t |= p1 ^ m1;
    t |= (p1 + m1) ^ NTRU_WEIGHT;
    t = (~t + 1); // two's complement
    t >>= 63;
    return (int) t;
}

void owcpa_samplemsg(unsigned char msg[NTRU_OWCPA_MSGBYTES],
        const unsigned char seed[NTRU_SAMPLE_RM_BYTES]) {
    poly r, m;

    sample_rm(&r, &m, seed);

    poly_S3_tobytes(msg, &r);
    poly_S3_tobytes(msg + NTRU_PACK_TRINARY_BYTES, &m);
}

void owcpa_keypair(unsigned char *pk,
        unsigned char *sk,
        const unsigned char seed[NTRU_SAMPLE_FG_BYTES]) {
    int i;

    poly x1, x2, x3, x4, x5;

    poly *f = &x1, *invf_mod3 = &x2;
    poly *g = &x3, *G = &x2;
    poly *Gf = &x3, *invGf = &x4, *tmp = &x5;
    poly *invh = &x3, *h = &x3;

    sample_fg(f, g, seed);

    poly_S3_inv(invf_mod3, f);
    poly_S3_tobytes(sk, f);
    poly_S3_tobytes(sk + NTRU_PACK_TRINARY_BYTES, invf_mod3);

    /* Lift coeffs of f from Z_p to signed Z_p */
    poly_Z3_to_SignedZ3(f);

    /* Lift coeffs of g from Z_p to Z_q */
    poly_Z3_to_Zq(g);

    /* G = 3*g */
    for (i = 0; i < NTRU_N; i++) {
        G->coeffs[i] = MODQ(3 * g->coeffs[i]);
    }

    poly_SignedZ3_Rq_mul(Gf, f, G);

    poly_Rq_inv(invGf, Gf);

    poly_SignedZ3_Rq_mul(tmp, f, invGf);
    poly_SignedZ3_Sq_mul(invh, f, tmp);
    poly_Sq_tobytes(sk + 2 * NTRU_PACK_TRINARY_BYTES, invh);

    poly_Rq_mul(tmp, invGf, G);
    poly_Rq_mul(h, tmp, G);
    poly_Rq_sum_zero_tobytes(pk, h);
}


void owcpa_enc(unsigned char *c,
        const unsigned char *rm,
        const unsigned char *pk) {
    int i;
    poly x1, x2, x3;
    poly *h = &x1, *liftm = &x1;
    poly *r = &x2, *m = &x2;
    poly *ct = &x3;

    poly_Rq_sum_zero_frombytes(h, pk);

    poly_S3_frombytes(r, rm);
    poly_Z3_to_SignedZ3(r);

    poly_SignedZ3_Rq_mul(ct, r, h);

    poly_S3_frombytes(m, rm + NTRU_PACK_TRINARY_BYTES);
    poly_lift(liftm, m);
    for (i = 0; i < NTRU_N; i++) {
        ct->coeffs[i] = MODQ(ct->coeffs[i] + liftm->coeffs[i]);
    }

    poly_Rq_sum_zero_tobytes(c, ct);
}

int owcpa_dec(unsigned char *rm,
        const unsigned char *ciphertext,
        const unsigned char *secretkey) {
    int i;
    int fail;
    poly x1, x2, x3, x4;

    poly *c = &x1, *f = &x2, *cf = &x3;
    poly *mf = &x2, *finv3 = &x3, *m = &x4;
    poly *liftm = &x2, *invh = &x3, *r = &x4;
    poly *b = &x1;

    poly_Rq_sum_zero_frombytes(c, ciphertext);
    poly_S3_frombytes(f, secretkey);
    poly_Z3_to_SignedZ3(f);

    poly_SignedZ3_Rq_mul(cf, f, c);
    poly_Rq_to_S3(mf, cf);

    poly_S3_frombytes(finv3, secretkey + NTRU_PACK_TRINARY_BYTES);
    poly_S3_mul(m, mf, finv3);
    poly_S3_tobytes(rm + NTRU_PACK_TRINARY_BYTES, m);

    fail = 0;

    /* Check that the unused bits of the last byte of the ciphertext are zero */
    fail |= owcpa_check_ciphertext(ciphertext);

    /* NOTE: For the IND-CCA2 KEM we must ensure that c = Enc(h, (r,m)).       */
    /* We can avoid re-computing r*h + Lift(m) as long as we check that        */
    /* r (defined as b/h mod (q, Phi_n)) and m are in the message space.       */
    /* (m can take any value in S3 in NTRU_HRSS) */
    fail |= owcpa_check_m(m);

    /* b = c - Lift(m) mod (q, x^n - 1) */
    poly_lift(liftm, m);
    for (i = 0; i < NTRU_N; i++) {
        b->coeffs[i] = MODQ(c->coeffs[i] - liftm->coeffs[i]);
    }

    /* r = b / h mod (q, Phi_n) */
    poly_Sq_frombytes(invh, secretkey + 2 * NTRU_PACK_TRINARY_BYTES);
    poly_Sq_mul(r, b, invh);

    /* NOTE: Our definition of r as b/h mod (q, Phi_n) follows Figure 4 of     */
    /*   [Sch18] https://eprint.iacr.org/2018/1174/20181203:032458.            */
    /* This differs from Figure 10 of Saito--Xagawa--Yamakawa                  */
    /*   [SXY17] https://eprint.iacr.org/2017/1005/20180516:055500             */
    /* where r gets a final reduction modulo p.                                */
    /* We need this change to use Proposition 1 of [Sch18].                    */

    /* Proposition 1 of [Sch18] shows that re-encryption with (r,m) yields c.  */
    /* if and only if fail==0 after the following call to owcpa_check_r        */
    /* The procedure given in Fig. 8 of [Sch18] can be skipped because we have */
    /* c(1) = 0 due to the use of poly_Rq_sum_zero_{to,from}bytes.             */
    fail |= owcpa_check_r(r);

    poly_trinary_Zq_to_Z3(r);
    poly_S3_tobytes(rm, r);

    return fail;
}
