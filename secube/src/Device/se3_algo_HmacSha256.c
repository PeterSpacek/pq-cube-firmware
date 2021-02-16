#include "se3_algo_HmacSha256.h"


uint16_t se3_algo_HmacSha256_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx)
{
	B5_tHmacSha256Ctx* sha_hmac = (B5_tHmacSha256Ctx *) ctx;

	if (key->data_size <= 0) {
		return (SE3_ERR_PARAMS);
	}
	if (B5_HMAC_SHA256_RES_OK != B5_HmacSha256_Init(sha_hmac, key->data, key->data_size)) {
		SE3_TRACE(("[algo_sha256hmac_init.init] B5_HmacSha256_Init failed\n"));
		return (SE3_ERR_PARAMS);
	}

	return (SE3_OK);
}


uint16_t se3_algo_HmacSha256_update(
	uint8_t* ctx, uint16_t flags,
    uint16_t datain0_len, const uint8_t* datain0,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
	uint16_t* dataout_len, uint8_t* dataout)
{

	B5_tHmacSha256Ctx* sha_hmac = (B5_tHmacSha256Ctx *)ctx;

	bool do_update = (datain1_len > 0);
	bool do_finit = (flags & SE3_CRYPTO_FLAG_FINIT);

	if (do_update) {
		// update
		if (B5_HMAC_SHA256_RES_OK != B5_HmacSha256_Update(sha_hmac, datain1, datain1_len)) {
			SE3_TRACE(("[algo_sha256hmac_init.update] B5_HmacSha256_Update failed\n"));
			return SE3_ERR_HW;
		}
	}

	if (do_finit) {
		if (B5_HMAC_SHA256_RES_OK != B5_HmacSha256_Finit(sha_hmac, dataout)) {
			SE3_TRACE(("[algo_sha256hmac_init.update] B5_HmacSha256_Finit failed\n"));
			return SE3_ERR_HW;
		}
		*dataout_len = 32;
	}

	return(SE3_OK);
}
