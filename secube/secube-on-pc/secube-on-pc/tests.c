#include "L1.h"

typedef struct {
	size_t size;
	uint8_t* buf;
	uint8_t* buf_hw;
	uint8_t* buf_sw;
	uint8_t iv[B5_AES_IV_SIZE];
} test_buffers;

typedef struct {
	uint16_t se3mode;
	uint8_t b5mode;
	uint16_t key_id;
	uint16_t key_size;
	uint8_t* key_data;
	char name[32];
} test_spec;

static bool test_mode(se3_session* s, test_buffers* tb, test_spec* mode);
void test_randbuf(size_t len, void** buf)
{
	*buf = malloc(len);
	se3c_rand(len, *buf);
}

bool test_Aes(se3_session* s)
{
	enum {
		TEST_SIZE = 1 * 1024 * 1024,
		KEY_ID_128 = 500,
		KEY_ID_192 = 501,
		KEY_ID_256 = 502,
		N_KEYS = 3,
		N_MODES = 24
	};
	uint16_t r;
	size_t i;
	test_buffers tb;
	bool success = false;
	uint8_t key_data[32];
	test_spec modes[N_MODES] = {
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_ENC, KEY_ID_128, 16, key_data, "AES128 ECB encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_ENC, KEY_ID_192, 24, key_data, "AES192 ECB encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_ENC, KEY_ID_256, 32, key_data, "AES256 ECB encrypt" },

		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_DEC, KEY_ID_128, 16, key_data, "AES128 ECB decrypt" },
		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_DEC, KEY_ID_192, 24, key_data, "AES192 ECB decrypt" },
		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_ECB, B5_AES256_ECB_DEC, KEY_ID_256, 32, key_data, "AES256 ECB decrypt" },

		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_128, 16, key_data, "AES128 CBC encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_192, 24, key_data, "AES192 CBC encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_256, 32, key_data, "AES256 CBC encrypt" },

		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_128, 16, key_data, "AES128 CBC decrypt" },
		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_192, 24, key_data, "AES192 CBC decrypt" },
		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_CBC, B5_AES256_CBC_ENC, KEY_ID_256, 32, key_data, "AES256 CBC decrypt" },

		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_128, 16, key_data, "AES128 CFB encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_192, 24, key_data, "AES192 CFB encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_256, 32, key_data, "AES256 CFB encrypt" },

		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_128, 16, key_data, "AES128 CFB decrypt" },
		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_192, 24, key_data, "AES192 CFB decrypt" },
		{ SE3_DIR_DECRYPT | SE3_FEEDBACK_CFB, B5_AES256_CFB_ENC, KEY_ID_256, 32, key_data, "AES256 CFB decrypt" },

		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_128, 16, key_data, "AES128 CTR encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_192, 24, key_data, "AES192 CTR encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_CTR, B5_AES256_CTR, KEY_ID_256, 32, key_data, "AES256 CTR encrypt" },

		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_128, 16, key_data, "AES128 OFB encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_192, 24, key_data, "AES192 OFB encrypt" },
		{ SE3_DIR_ENCRYPT | SE3_FEEDBACK_OFB, B5_AES256_OFB, KEY_ID_256, 32, key_data, "AES256 OFB encrypt" }
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

	printf("\tInserting keys\n");
	se3c_rand(32, key_data);
	for (i = 0; i < N_KEYS; i++) {
		r = L1_key_edit(s, SE3_KEY_OP_UPSERT, &keys[i]);
		if (r != SE3_OK) {
			goto cleanup;
		}
	}

	se3c_rand(B5_AES_BLK_SIZE, tb.iv);
	for (i = 0; i < N_MODES; i++) {
		printf("\t%s\n", modes[i].name);
		if (!test_mode(s, &tb, &modes[i])) {
			goto cleanup;
		}
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
	uint16_t dataout_len = 0;
	uint16_t chunk = (SE3_CRYPTO_MAX_DATAIN / B5_AES_BLK_SIZE) *B5_AES_BLK_SIZE;
	size_t i = 0, n = 0, nrem = 0;
	bool set_iv = false;

	B5_Aes256_Init(&aes, mode->key_data, mode->key_size, mode->b5mode);
	n = (tb->size) / chunk;
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

	if (set_iv) {
		B5_Aes256_SetIV(&aes, tb->iv);
	}
	for (i = 0; i < n; i++) {
		B5_Aes256_Update(&aes, rp, sp, chunk / B5_AES_BLK_SIZE);
		sp += chunk;
		rp += chunk;
	}
	n = (tb->size) % chunk;
	if (n > 0) {
		B5_Aes256_Update(&aes, rp, sp, (uint16_t)(n / B5_AES_BLK_SIZE));
	}

	sp = tb->buf;
	rp = tb->buf_hw;
	r = L1_crypto_init(s, SE3_ALGO_AES, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CBC, mode->key_id, &session_id);
	if (SE3_OK != r) {
		return false;
	}

	if (set_iv) {
		r = L1_crypto_update(s, session_id, SE3_CRYPTO_FLAG_SETIV, B5_AES_IV_SIZE, tb->iv, 0, NULL, &dataout_len, NULL);
		if ((SE3_OK != r) || (0 != dataout_len)) {
			return false;
		}
	}

	n = (tb->size) / chunk;
	nrem = (tb->size) % chunk;
	for (i = 0; i < n; i++) {
		r = L1_crypto_update(s, session_id,
			((nrem == 0) && (i == n - 1)) ? (SE3_CRYPTO_FLAG_FINIT) : 0,
			0, NULL, chunk, sp, &dataout_len, rp);
		if ((SE3_OK != r) || (chunk != dataout_len)) {
			return false;
		}
		sp += chunk;
		rp += chunk;
	}
	if (nrem > 0) {
		r = L1_crypto_update(s, session_id, SE3_CRYPTO_FLAG_FINIT, 0, NULL, (uint16_t)nrem, sp, &dataout_len, rp);
		if ((SE3_OK != r) || (nrem != dataout_len)) {
			return false;
		}
	}

	if (memcmp(tb->buf_sw, tb->buf_hw, tb->size)) {
		return false;
	}

	return true;
}
