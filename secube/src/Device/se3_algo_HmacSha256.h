#pragma once
#include "se3_security_core.h"

/** \brief SE3_ALGO_HMACSHA256 update handler
 *  
 *  Mode is not used
 */
uint16_t se3_algo_HmacSha256_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx);

/** \brief SE3_ALGO_HMACSHA256 update handler
 *
 *  Supported operations
 *  (default): update HmacSha256 context with datain1
 *  SE3_CRYPTO_FLAG_FINIT: produce authentication tag in dataout and release session
 *  
 *  Contribution of each operation to the output size:
 *    (default): + 0
 *    SE3_CRYPTO_FLAG_FINIT: + B5_SHA256_DIGEST_SIZE
 */
uint16_t se3_algo_HmacSha256_update(
	uint8_t* ctx, uint16_t flags,
    uint16_t datain0_len, const uint8_t* datain0,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
	uint16_t* dataout_len, uint8_t* dataout);
