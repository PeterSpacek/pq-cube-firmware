#include "tests.h"

typedef struct {
	size_t size;
	uint8_t* buf;
	uint8_t* buf_hw;
	uint8_t* buf_sw;
	uint8_t iv[B5_AES_IV_SIZE];
} test_buffers;

typedef struct {
	uint8_t direction;
	uint16_t se3mode;
	uint8_t b5mode;
	uint16_t key_id;
	uint16_t key_size;
	uint8_t* key_data;
	char name[32];
} test_spec;

static bool test_mode(se3_session* s, test_buffers* tb, test_spec* mode);


bool test_AesHmacSha256s(se3_session* s)
{
	enum {
		TEST_SIZE = 1 * 1024 * 1024 + B5_SHA256_DIGEST_SIZE,
		KEY_ID_128 = 500,
		KEY_ID_192 = 501,
		KEY_ID_256 = 502,
		N_KEYS = 3,
		N_MODES = 30
	};
	uint16_t r;
	bool b;
	size_t i;
	test_buffers tb;
	bool success = false;
	size_t rep;
	uint8_t key_data[32];
	test_spec modes[N_MODES] = {
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_ENC, KEY_ID_128, 16, key_data, "AES128 ECB HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_ENC, KEY_ID_192, 24, key_data, "AES192 ECB HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_ENC, KEY_ID_256, 32, key_data, "AES256 ECB HMAC-SHA256 encrypt" },

		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_DEC, KEY_ID_128, 16, key_data, "AES128 ECB HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_DEC, KEY_ID_192, 24, key_data, "AES192 ECB HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_DEC, KEY_ID_256, 32, key_data, "AES256 ECB HMAC-SHA256 decrypt" },

		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_128, 16, key_data, "AES128 CBC HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_192, 24, key_data, "AES192 CBC HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_256, 32, key_data, "AES256 CBC HMAC-SHA256 encrypt" },

		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_DEC, KEY_ID_128, 16, key_data, "AES128 CBC HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_DEC, KEY_ID_192, 24, key_data, "AES192 CBC HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_DEC, KEY_ID_256, 32, key_data, "AES256 CBC HMAC-SHA256 decrypt" },

		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_128, 16, key_data, "AES128 CFB HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_192, 24, key_data, "AES192 CFB HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_256, 32, key_data, "AES256 CFB HMAC-SHA256 encrypt" },

		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_DEC, KEY_ID_128, 16, key_data, "AES128 CFB HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_DEC, KEY_ID_192, 24, key_data, "AES192 CFB HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_DEC, KEY_ID_256, 32, key_data, "AES256 CFB HMAC-SHA256 decrypt" },

		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_128, 16, key_data, "AES128 CTR HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_192, 24, key_data, "AES192 CTR HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_256, 32, key_data, "AES256 CTR HMAC-SHA256 encrypt" },

		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_128, 16, key_data, "AES128 CTR HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_192, 24, key_data, "AES192 CTR HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_256, 32, key_data, "AES256 CTR HMAC-SHA256 decrypt" },

		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_128, 16, key_data, "AES128 OFB HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_192, 24, key_data, "AES192 OFB HMAC-SHA256 encrypt" },
		{ 0, SE3_DIR_ENCRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_256, 32, key_data, "AES256 OFB HMAC-SHA256 encrypt" },

		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_128, 16, key_data, "AES128 OFB HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_192, 24, key_data, "AES192 OFB HMAC-SHA256 decrypt" },
		{ 1, SE3_DIR_DECRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_256, 32, key_data, "AES256 OFB HMAC-SHA256 decrypt" }
	};

	se3_key keys[N_KEYS] = {
		{ KEY_ID_128, (uint32_t)time(0) + 365 * 24 * 3600, B5_AES_128, 5, {0}, key_data, "tk128" },
		{ KEY_ID_192, (uint32_t)time(0) + 365 * 24 * 3600, B5_AES_192, 5, {0}, key_data, "tk192" },
		{ KEY_ID_256, (uint32_t)time(0) + 365 * 24 * 3600, B5_AES_256, 5, {0}, key_data, "tk256" }
	};

	test_randbuf(TEST_SIZE, &tb.buf);
	tb.buf_hw = (uint8_t*)malloc(TEST_SIZE);
	tb.buf_sw = (uint8_t*)malloc(TEST_SIZE);
	tb.size = TEST_SIZE;

	se3c_rand(32, key_data);
	for (i = 0; i < N_KEYS; i++) {
		r = L1_key_edit(s, SE3_KEY_OP_UPSERT, &keys[i]);
		if (r != SE3_OK) {
			printf("Error inserting keys\n");
			goto cleanup;
		}
	}

	se3c_rand(B5_AES_BLK_SIZE, tb.iv);
	for (i = 0; i < N_MODES; i++) {
		printf("%s ", modes[i].name);
		for (rep = 0; rep < NRUN; rep++) {
			b = test_mode(s, &tb, &modes[i]);
			printf(" ");
			if (!b) {
				goto cleanup;
			}
		}
		printf("\n");
	}

	success = true;
cleanup:
	free(tb.buf);
	free(tb.buf_hw);
	free(tb.buf_sw);
	return success;
}



static bool test_mode(se3_session* s, test_buffers* tb, test_spec* mode)
{
	uint32_t session_id;
	uint16_t r = SE3_OK;
	uint8_t* sp, *rp;
	B5_tAesCtx aes;
	B5_tHmacSha256Ctx hmac;
	uint16_t dataout_len = 0;
	uint16_t chunk = ((SE3_CRYPTO_MAX_DATAIN - B5_SHA256_DIGEST_SIZE) / B5_AES_BLK_SIZE) *B5_AES_BLK_SIZE;
	size_t i = 0, n = 0, nrem = 0;
	bool set_iv = false;
	stopwatch sw;
	bool dir_encrypt = false;
	bool finit;
	size_t size = tb->size - B5_SHA256_DIGEST_SIZE;

	uint8_t keys[2 * B5_AES_256];
	uint8_t* aes_key = keys, *hmac_key = keys + mode->key_size;
	uint8_t* encbuf;

	PBKDF2HmacSha256(mode->key_data, mode->key_size, NULL, 0, 1, keys, 2 * mode->key_size);

	B5_HmacSha256_Init(&hmac, hmac_key, mode->key_size);

	B5_Aes256_Init(&aes, aes_key, mode->key_size, mode->b5mode);
	n = (size) / chunk;

	dir_encrypt = !(mode->direction);

	switch (mode->b5mode) {
	case B5_AES256_ECB_DEC:
	case B5_AES256_CBC_DEC:
	case B5_AES256_CFB_DEC:
		rp = tb->buf; sp = tb->buf_sw;
		break;
	default:
		sp = tb->buf; rp = tb->buf_sw;
	}
	switch (mode->b5mode) {
	case B5_AES256_ECB_ENC:
	case B5_AES256_ECB_DEC:
		set_iv = false; break;
	default:
		set_iv = true;
	}

	encbuf = rp;
	if (!dir_encrypt) {
		switch (mode->b5mode) {
		case B5_AES256_OFB:
		case B5_AES256_CTR:
			encbuf = sp;
			break;
		}
	}


	if (set_iv) {
		B5_Aes256_SetIV(&aes, tb->iv);
		B5_HmacSha256_Update(&hmac, tb->iv, B5_AES_IV_SIZE);
	}

	for (i = 0; i < n; i++) {
		if (!dir_encrypt)B5_HmacSha256_Update(&hmac, encbuf, chunk);
		B5_Aes256_Update(&aes, rp, sp, chunk / B5_AES_BLK_SIZE);
		if (dir_encrypt)B5_HmacSha256_Update(&hmac, encbuf, chunk);
		sp += chunk;
		rp += chunk;
		encbuf += chunk;
	}
	n = (size) % chunk;
	if (n > 0) {
		if (!dir_encrypt)B5_HmacSha256_Update(&hmac, encbuf, (uint16_t)n);
		B5_Aes256_Update(&aes, rp, sp, (uint16_t)(n / B5_AES_BLK_SIZE));
		if (dir_encrypt)B5_HmacSha256_Update(&hmac, encbuf, (uint16_t)n);
		rp += n;
		sp += n;
		encbuf += n;
	}
	switch (mode->b5mode) {
	case B5_AES256_ECB_DEC:
	case B5_AES256_CBC_DEC:
	case B5_AES256_CFB_DEC:
		B5_HmacSha256_Finit(&hmac, sp);
		break;
	default:
		B5_HmacSha256_Finit(&hmac, rp);
	}
	/*if (dir_encrypt) {
		B5_HmacSha256_Finit(&hmac, rp);
	}
	else {
		B5_HmacSha256_Finit(&hmac, sp);
	}*/

	sp = tb->buf;
	rp = tb->buf_hw;
	stopwatch_start(&sw);
	r = L1_crypto_init(s, SE3_ALGO_AES_HMACSHA256, mode->se3mode, mode->key_id, &session_id);
	if (SE3_OK != r) {
		return false;
	}

	if (set_iv) {
		r = L1_crypto_update(s, session_id, SE3_CRYPTO_FLAG_RESET, B5_AES_IV_SIZE, tb->iv, 0, NULL, &dataout_len, NULL);
		if ((SE3_OK != r) || (0 != dataout_len)) {
			return false;
		}
	}
	else {
		r = L1_crypto_update(s, session_id, SE3_CRYPTO_FLAG_RESET, 0, NULL, 0, NULL, &dataout_len, NULL);
		if ((SE3_OK != r) || (0 != dataout_len)) {
			return false;
		}
	}

	n = (size) / chunk;
	nrem = (size) % chunk;
	for (i = 0; i < n; i++) {
		finit = ((nrem == 0) && (i == n - 1));
		r = L1_crypto_update(s, session_id,
			finit ? (SE3_CRYPTO_FLAG_AUTH | SE3_CRYPTO_FLAG_FINIT) : 0,
			0, NULL, chunk, sp, &dataout_len, rp);
		if ((SE3_OK != r) || (chunk + (finit?(B5_SHA256_DIGEST_SIZE):0) != dataout_len)) {
			return false;
		}
		sp += chunk;
		rp += chunk;
	}
	if (nrem > 0) {
		r = L1_crypto_update(s, session_id, SE3_CRYPTO_FLAG_AUTH | SE3_CRYPTO_FLAG_FINIT, 0, NULL, (uint16_t)nrem, sp, &dataout_len, rp);
		if ((SE3_OK != r) || (nrem + B5_SHA256_DIGEST_SIZE != dataout_len)) {
			return false;
		}
	}
	stopwatch_stop(&sw);

	if (memcmp(tb->buf_sw, tb->buf_hw, tb->size)) {
		return false;
	}

	test_printspeed(&sw, size);

	return true;
}