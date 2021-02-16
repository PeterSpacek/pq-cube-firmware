#include "tests.h"

typedef struct {
	size_t size;
	uint8_t* buf;
	uint8_t buf_hw[B5_SHA256_DIGEST_SIZE];
	uint8_t buf_sw[B5_SHA256_DIGEST_SIZE];
} test_buffers;

bool test_Sha256(se3_session* s)
{
	enum {
		TEST_SIZE = 1 * 1024 * 1024,
	};
	uint8_t* buf;
	uint8_t buf_sw[B5_SHA256_DIGEST_SIZE];
	uint8_t buf_hw[B5_SHA256_DIGEST_SIZE];
	bool success = false;

	uint32_t session_id;
	uint16_t r = SE3_OK;
	uint8_t* sp;
	size_t rep = 0;
	B5_tSha256Ctx sha;
	uint16_t dataout_len = 0;
	uint16_t chunk = (SE3_CRYPTO_MAX_DATAIN / B5_AES_BLK_SIZE) *B5_AES_BLK_SIZE;
	size_t i = 0, n = 0, nrem = 0;
	bool finit = false;
	stopwatch sw;

	test_randbuf(TEST_SIZE, &buf);

	printf("SHA256 ");
	
	for (rep = 0; rep < NRUN; rep++) {
		B5_Sha256_Init(&sha);
		sp = buf;
		n = TEST_SIZE / chunk;
		for (i = 0; i < n; i++) {
			B5_Sha256_Update(&sha, sp, chunk);
			sp += chunk;
		}
		n = TEST_SIZE % chunk;
		if (n > 0) {
			B5_Sha256_Update(&sha, sp, n);
		}
		B5_Sha256_Finit(&sha, buf_sw);

		sp = buf;
		stopwatch_start(&sw);
		r = L1_crypto_init(s, SE3_ALGO_SHA256, 0, SE3_KEY_INVALID, &session_id);
		if (SE3_OK != r) {
			goto cleanup;
		}

		n = TEST_SIZE / chunk;
		nrem = TEST_SIZE % chunk;
		for (i = 0; i < n; i++) {
			finit = (nrem == 0) && (i == n - 1);
			r = L1_crypto_update(s, session_id,
				(finit) ? (SE3_CRYPTO_FLAG_AUTH | SE3_CRYPTO_FLAG_FINIT) : 0,
				chunk, sp, 0, NULL, &dataout_len, buf_hw);
			if ((SE3_OK != r) ||
				(finit && (B5_SHA256_DIGEST_SIZE != dataout_len)) ||
				(!finit && (0 != dataout_len)))
			{
				goto cleanup;
			}
			sp += chunk;
		}
		if (nrem > 0) {
			r = L1_crypto_update(s, session_id, SE3_CRYPTO_FLAG_AUTH | SE3_CRYPTO_FLAG_FINIT, (uint16_t)nrem, sp, 0, NULL, &dataout_len, buf_hw);
			if ((SE3_OK != r) || (B5_SHA256_DIGEST_SIZE != dataout_len)) {
				goto cleanup;
			}
		}
		stopwatch_stop(&sw);

		if (memcmp(buf_sw, buf_hw, B5_SHA256_DIGEST_SIZE)) {
			goto cleanup;
		}
		test_printspeed(&sw, TEST_SIZE);
		printf(" ");
	}
	printf("\n");


	success = true;
cleanup:
	free(buf);
	return success;
}

