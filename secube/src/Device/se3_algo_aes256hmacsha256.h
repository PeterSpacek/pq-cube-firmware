#pragma once
#include "se3_security_core.h"
#include "pbkdf2.h"

#define PBKDF2_SALT_LEN	32
#define PBKDF2_ITERATION 1000
#define PBKDF2_INPUT_KEY_LEN 32
#define PBKDF2_OUTPUT_KEY_LEN 64

uint16_t se3_algo_aes256hmacsha256_init(
    se3_flash_key* key, uint16_t mode, uint8_t* ctx);

uint16_t se3_algo_aes256hmacsha256_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain0_len, const uint8_t* datain0,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout);
