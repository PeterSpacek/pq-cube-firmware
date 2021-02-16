/**
 *  \file se3_algo_Aes.h
 *  \author Nicola Ferri
 *  \brief SE3_ALGO_AES crypto handlers
 */

#pragma once
#include "se3_security_core.h"

/** \brief SE3_ALGO_AES init handler
 *  
 *  Supported modes
 *  Any combination of one of {SE3_DIR_ENCRYPT, SE3_DIR_DECRYPT} and one of
 *    {SE3_FEEDBACK_ECB, SE3_FEEDBACK_CBC, SE3_FEEDBACK_CFB, SE3_FEEDBACK_OFB, SE3_FEEDBACK_CTR}
 *  
 *  Supported key sizes
 *  128-bit, 192-bit, 256-bit
 */
uint16_t se3_algo_Aes_init(
    se3_flash_key* key, uint16_t mode, uint8_t* ctx);


/** \brief SE3_ALGO_AES update handler
 *
 *  Supported operations
 *  (default): encrypt/decrypt datain2 and update HmacSha256 context with datain2. Not executed
 *    if datain2 is empty (zero-length)
 *  SE3_CRYPTO_FLAG_SETIV: set new IV from datain1
 *  SE3_CRYPTO_FLAG_FINIT: release session
 *
 *  Combined operations are executed in the following order:
 *    SE3_CRYPTO_FLAG_SETIV
 *    (default)
 *    SE3_CRYPTO_FLAG_FINIT
 *
 *  Contribution of each operation to the output size:
 *    (default): + datain2_len
 *    Others: + 0
 */
uint16_t se3_algo_Aes_update(
    uint8_t* ctx, uint16_t flags,
    uint16_t datain0_len, const uint8_t* datain0,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
    uint16_t* dataout_len, uint8_t* dataout);
