#ifndef SABER_M4_INDCPA_H
#define SABER_M4_INDCPA_H

#include <stdint.h>

void SABER_M4_indcpa_keypair(uint8_t *pk, uint8_t *sk);

void SABER_M4_indcpa_client(uint8_t *pk, uint8_t *b_prime, uint8_t *c, uint8_t *key);

void SABER_M4_indcpa_server(uint8_t *pk, uint8_t *b_prime, uint8_t *c, uint8_t *key);

void SABER_M4_indcpa_kem_keypair(uint8_t *pk, uint8_t *sk);
void SABER_M4_indcpa_kem_enc(uint8_t *message, uint8_t *noiseseed, uint8_t *pk,  uint8_t *ciphertext);
void SABER_M4_indcpa_kem_dec(uint8_t *sk, uint8_t *ciphertext, uint8_t message_dec[]);

int SABER_M4_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int SABER_M4_crypto_kem_enc(unsigned char *c, unsigned char *k, const unsigned char *pk);
int SABER_M4_crypto_kem_dec(unsigned char *k, const unsigned char *c, const unsigned char *sk);



#endif

