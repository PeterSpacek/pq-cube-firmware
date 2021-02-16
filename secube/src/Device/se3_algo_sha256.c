#include "se3_algo_sha256.h"


// key is not used;  mode is not used
uint16_t se3_algo_Sha256_init(se3_flash_key* key, uint16_t mode, uint8_t* ctx) {
	B5_tSha256Ctx* sha = (B5_tSha256Ctx*)ctx;
	
	if (B5_SHA256_RES_OK != B5_Sha256_Init(sha)) {
		SE3_TRACE(("[algo_sha256.init] B5_Sha256_Init failed\n"));
		return (SE3_ERR_PARAMS);
	}
	
	return (SE3_OK);
}


// datain2 is not used; datain2_len is not used
uint16_t se3_algo_Sha256_update(
	uint8_t* ctx, uint16_t flags,
    uint16_t datain0_len, const uint8_t* datain0,
    uint16_t datain1_len, const uint8_t* datain1,
    uint16_t datain2_len, const uint8_t* datain2,
	uint16_t* dataout_len, uint8_t* dataout) {

	B5_tSha256Ctx* sha = (B5_tSha256Ctx*)ctx;

	bool do_update = (datain1_len > 0);
	bool do_finit = (flags & SE3_CRYPTO_FLAG_FINIT);

	if (do_update) {
		// update
		if (B5_SHA256_RES_OK != B5_Sha256_Update(sha, datain1, datain1_len)) {
			SE3_TRACE(("[algo_sha256.update] B5_Sha256_Update failed\n"));
			return SE3_ERR_HW;
		}
	}

	if (do_finit) {
		if (B5_SHA256_RES_OK != B5_Sha256_Finit(sha, dataout)) {
			SE3_TRACE(("[algo_sha256.update] B5_Sha256_Finit failed\n"));
			return SE3_ERR_HW;
		}
		*dataout_len = 32;
	}

	return(SE3_OK);
}
