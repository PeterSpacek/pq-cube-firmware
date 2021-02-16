#include "tests.h"

typedef struct {
	size_t size;
	uint8_t* buf;
	uint8_t buf_hw[B5_SHA256_DIGEST_SIZE];
	uint8_t buf_sw[B5_SHA256_DIGEST_SIZE];
} test_buffers;

typedef struct {
	uint16_t key_id;
	uint16_t key_size;
	uint8_t* key_data;
	char name[32];
} test_spec;

static bool test_mode(se3_session* s, test_buffers* tb, test_spec* mode);


bool test_HmacSha256(se3_session* s)
{
	enum {
		TEST_SIZE = 1 * 1024 * 1024,
		KEY_ID_128 = 500,
		KEY_ID_192 = 501,
		KEY_ID_256 = 502,
		N_KEYS = 3,
		N_MODES = 3
	};
	uint16_t r;
	size_t i;
	bool b;
	test_buffers tb;
	bool success = false;
	size_t rep;
	uint8_t key_data[32];
	test_spec modes[N_MODES] = {
		{ KEY_ID_128, 16, key_data, "HMAC-SHA256 128-bit key" },
		{ KEY_ID_192, 24, key_data, "HMAC-SHA256 192-bit key" },
		{ KEY_ID_256, 32, key_data, "HMAC-SHA256 256-bit key" }
	};

	se3_key keys[N_KEYS] = {
		{ KEY_ID_128, (uint32_t)time(0) + 365 * 24 * 3600, B5_AES_128, 5, {0}, key_data, "tk128" },
		{ KEY_ID_192, (uint32_t)time(0) + 365 * 24 * 3600, B5_AES_192, 5, {0}, key_data, "tk192" },
		{ KEY_ID_256, (uint32_t)time(0) + 365 * 24 * 3600, B5_AES_256, 5, {0}, key_data, "tk256" }
	};

	test_randbuf(TEST_SIZE, &tb.buf);
	tb.size = TEST_SIZE;

	se3c_rand(32, key_data);
	for (i = 0; i < N_KEYS; i++) {
		r = L1_key_edit(s, SE3_KEY_OP_UPSERT, &keys[i]);
		if (r != SE3_OK) {
			printf("Error inserting keys\n");
			goto cleanup;
		}
	}

	for (i = 0; i < N_MODES; i++) {
		printf("%s ", modes[i].name);
		for (rep = 0; rep < NRUN; rep++) {
			b = test_mode(s, &tb, &modes[i]);
			if (!b) {
				goto cleanup;
			}
			printf(" ");
		}
		printf("\n");
	}

	success = true;
cleanup:
	free(tb.buf);
	return success;
}



static bool test_mode(se3_session* s, test_buffers* tb, test_spec* mode)
{
	uint32_t session_id;
	uint16_t r = SE3_OK;
	uint8_t* sp;
	B5_tHmacSha256Ctx hmac;
	uint16_t dataout_len = 0;
	uint16_t chunk = (SE3_CRYPTO_MAX_DATAIN / B5_AES_BLK_SIZE) *B5_AES_BLK_SIZE;
	size_t i = 0, n = 0, nrem = 0;
	bool finit = false;
	stopwatch sw;

	B5_HmacSha256_Init(&hmac, mode->key_data, mode->key_size);
	sp = tb->buf;
	n = (tb->size) / chunk;
	for (i = 0; i < n; i++) {
		B5_HmacSha256_Update(&hmac, sp, chunk);
		sp += chunk;
	}
	n = (tb->size) % chunk;
	if (n > 0) {
		B5_HmacSha256_Update(&hmac, sp, n);
	}
	B5_HmacSha256_Finit(&hmac, tb->buf_sw);

	sp = tb->buf;
	stopwatch_start(&sw);
	r = L1_crypto_init(s, SE3_ALGO_HMACSHA256, 0, mode->key_id, &session_id);
	if (SE3_OK != r) {
		return false;
	}

	n = (tb->size) / chunk;
	nrem = (tb->size) % chunk;
	for (i = 0; i < n; i++) {
		finit = (nrem == 0) && (i == n - 1);
		r = L1_crypto_update(s, session_id,
			(finit) ? (SE3_CRYPTO_FLAG_AUTH | SE3_CRYPTO_FLAG_FINIT) : 0,
			chunk, sp, 0, NULL, &dataout_len, tb->buf_hw);
		if ((SE3_OK != r) || 
			(finit && (B5_SHA256_DIGEST_SIZE != dataout_len)) || 
			(!finit && (0 != dataout_len)))
		{
			return false;
		}
		sp += chunk;
	}
	if (nrem > 0) {
		r = L1_crypto_update(s, session_id, SE3_CRYPTO_FLAG_AUTH | SE3_CRYPTO_FLAG_FINIT, (uint16_t)nrem, sp, 0, NULL, &dataout_len, tb->buf_hw);
		if ((SE3_OK != r) || (B5_SHA256_DIGEST_SIZE != dataout_len)) {
			return false;
		}
	}
	stopwatch_stop(&sw);

	if (memcmp(tb->buf_sw, tb->buf_hw, B5_SHA256_DIGEST_SIZE)) {
		return false;
	}
	test_printspeed(&sw, tb->size);

	return true;
}
