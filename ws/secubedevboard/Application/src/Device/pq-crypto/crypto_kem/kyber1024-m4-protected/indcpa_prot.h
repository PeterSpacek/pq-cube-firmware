#ifndef INDCPA_prot_H
#define INDCPA_prot_H

void indcpa_keypair_prot(unsigned char *pk,
                    unsigned char *sk);

void indcpa_enc_prot(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coins);

unsigned char indcpa_enc_cmp_prot(const unsigned char *ct,
                             const unsigned char *m,
                             const unsigned char *pk,
                             const unsigned char *coins);

void indcpa_dec_prot(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk);

#endif
