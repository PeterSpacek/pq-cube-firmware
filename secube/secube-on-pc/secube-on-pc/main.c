#include <Windows.h>
#include <stdint.h>
#include "stubs.h"
#include "device_main.h"
#include "L1.h"

#include <assert.h>

#pragma warning(disable:4996)

static uint8_t test_key[32] = {
	0x99, 0x5, 0xae, 0xc3, 0x98, 0xd6, 0x26, 0x35, 0xcd, 0xf7, 0x28, 0xf6, 0xd8, 0xd3, 0x9, 0xe8,
	0xee, 0xa, 0x59, 0xce, 0x6, 0xb6, 0x39, 0x6a, 0x10, 0x8f, 0x47, 0xbc, 0xfe, 0x4f, 0xb2, 0x8d
};

static uint8_t serialno[32] = {
    0xe2, 0xf2, 0xb3, 0x42, 0xf4, 0xa3, 0x52, 0x89, 0xf4, 0x94, 0x30, 0xfa, 0x2c, 0xd5, 0x1b, 0x45,
    0x7f, 0xd2, 0x29, 0x9, 0xd1, 0xcd, 0x24, 0x65, 0x16, 0xc1, 0xf4, 0xce, 0x24, 0xa2, 0xc3, 0x67 };

static uint8_t pin0[32] = {
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

static uint8_t ciao[32] = {
	'c','i','a','o', 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

static char testkey_name[8] = "testkey";
static HANDLE sim_thread = INVALID_HANDLE_VALUE;

DWORD WINAPI DeviceMain(LPVOID lpParam)
{
	device_loop();
	return 0;
}

void sim_init()
{
    stubs_init();
}

void sim_start()
{
    DWORD dwThreadId;
	stubs_init();
	device_init();
	sim_thread = CreateThread(NULL, 0, DeviceMain, NULL, 0, &dwThreadId);
}

uint32_t randui32()
{
	uint32_t tmp;
	se3c_rand(4, (uint8_t*)&tmp);
	return tmp;
}

void test_echo(se3_device* dev)
{
    enum {
        TEST_SIZE = 1 * 1024 * 1024
    };
    uint8_t* sendbuf = (uint8_t*)malloc(TEST_SIZE);
    uint8_t* recvbuf = (uint8_t*)malloc(TEST_SIZE);
    size_t n, i;
    uint16_t r = SE3_OK;
    uint8_t* sp = sendbuf, *rp = recvbuf;
    uint64_t t;

    se3c_rand(TEST_SIZE, sendbuf);

    t = se3c_clock();
    n = TEST_SIZE / SE3_REQ_MAX_DATA;
    for (i = 0; i < n; i++) {
        r = L0_echo(dev, sp, SE3_REQ_MAX_DATA, rp);
        assert(SE3_OK == r);
        sp += SE3_REQ_MAX_DATA;
        rp += SE3_REQ_MAX_DATA;
    }
    n = TEST_SIZE%SE3_REQ_MAX_DATA;
    if (n > 0) {
        L0_echo(dev, sp, (uint16_t)n, rp);
        assert(SE3_OK == r);
    }
    t = se3c_clock() - t;
    assert(!memcmp(sendbuf, recvbuf, TEST_SIZE));
    printf("SPEED %.3f KiB/s\n", (float)(((double)TEST_SIZE / 1024.0) / ((double)t / 1000.0)));


    free(sendbuf);
    free(recvbuf);
}


void print_keys(se3_session* s)
{
    uint16_t r;
    uint16_t count = 0;
    se3_key keys[50];
    char tmp[SE3_KEY_NAME_MAX + 1];
    size_t i;

    r = L1_key_list(s, 0, 50, NULL, keys, &count);
    assert(SE3_OK == r);

    printf("read %u keys\n", (unsigned)count);
    for (i = 0; i < count; i++) {
        memcpy(tmp, keys[i].name, keys[i].name_size);
        tmp[keys[i].name_size] = '\0';
        printf("NAME %s\n", tmp);
        printf("  SIZE %u\n", (unsigned)keys[i].data_size);
        printf("   VAL %u\n", (unsigned)keys[i].validity);
    }
    printf("\n");
}


void test_aes256(se3_session* s, uint32_t key_id)
{
    enum {
        TEST_SIZE = 128 * 1024
    };
    uint32_t sid;
    uint8_t* sendbuf = (uint8_t*)malloc(TEST_SIZE);
    uint8_t* recvbuf = (uint8_t*)malloc(TEST_SIZE);
    uint8_t* expected = (uint8_t*)malloc(TEST_SIZE);

    size_t n, i;
    uint16_t r = SE3_OK;
    uint8_t* sp = sendbuf, *rp = recvbuf;
    uint64_t t;
    B5_tAesCtx aes;
    uint16_t dataout_len = 0;

    uint16_t chunk = (SE3_CRYPTO_MAX_DATAIN / B5_AES_BLK_SIZE)*B5_AES_BLK_SIZE;

    se3c_rand(TEST_SIZE, sendbuf);

    B5_Aes256_Init(&aes, test_key, 32, B5_AES256_ECB_ENC);
    B5_Aes256_Update(&aes, expected, sendbuf, (uint16_t)(TEST_SIZE / B5_AES_BLK_SIZE));
    B5_Aes256_Finit(&aes);

    r = L1_crypto_init(s, SE3_ALGO_AES, SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, key_id, &sid);
    assert(SE3_OK == r);
    assert(SE3_SESSION_INVALID != sid);

    //r = L1_crypto_update(s, sid, 0, B5_AES_IV_SIZE, test_key, 0, NULL, &dataout_len, rp);
    //assert(SE3_OK == r);

    t = se3c_clock();
    n = TEST_SIZE / chunk;
    for (i = 0; i < n; i++) {
        r = L1_crypto_update(s, sid, 0, 0, NULL, chunk, sp, &dataout_len, rp);
        assert(SE3_OK == r);
        assert(chunk == dataout_len);
        sp += chunk;
        rp += chunk;
    }
    n = TEST_SIZE%chunk;
    if (n > 0) {
        r = L1_crypto_update(s, sid, 0, 0, NULL, (uint16_t)n, sp, &dataout_len, rp);
        assert(SE3_OK == r);
        assert(n == dataout_len);
    }
    t = se3c_clock() - t;
    assert(!memcmp(expected, recvbuf, TEST_SIZE));
    printf("SPEED %.3f KiB/s\n", (float)(((double)TEST_SIZE / 1024.0) / ((double)t / 1000.0)));


    free(sendbuf);
    free(recvbuf);
    free(expected);
}

#define MAX_INIT_PIN 32
#define ADMIN_PIN_LEN 13
#define ADMIN_PIN (uint8_t*)"myNewAdminPin"
#define USER_PIN_LEN 12
#define USER_PIN (uint8_t*)"myNewUserPin"
#define KEY_TO_DELETE	100
#define KEY_ARRAY_LEN
/*These next values should be changed*/
#define DATA1_LEN	15104	
#define DATA2_LEN	15104
#define DATAOUT_LEN	15104


uint16_t test_login(se3_device *dev)
{

	uint16_t return_value = 0;
	uint8_t init_pin[MAX_INIT_PIN];
	se3_session s;
	memset(init_pin, 0, MAX_INIT_PIN);

	return_value = L1_login(&s, dev, init_pin, SE3_ACCESS_ADMIN);	//Try init_pin on Admin login
	assert(!return_value);
	return_value = L1_set_admin_PIN(&s, ADMIN_PIN);					//Change Admin pin 
	assert(!return_value);
	return_value = L1_logout(&s);									//Logout
	assert(!return_value);

	return_value = L1_login(&s, dev, init_pin, SE3_ACCESS_USER);	//Try init_pin on User login
	assert(!return_value);
	return_value = L1_logout(&s);									//Logout
	assert(!return_value);

	return_value = L1_login(&s, dev, ADMIN_PIN, SE3_ACCESS_ADMIN);	//Login as Admin with new pin
	assert(!return_value);
	return_value = L1_set_user_PIN(&s, USER_PIN);					//Change User pin
	assert(!return_value);
	return_value = L1_logout(&s);									//Logout
	assert(!return_value);

	return_value = L1_login(&s, dev, ADMIN_PIN, SE3_ACCESS_USER);	//Login as User with WRONG pin
	assert(return_value);
	
	return return_value? 0 : 1;
}

uint32_t current_time = 0;

uint16_t test_keys(se3_device *dev)
{
	uint16_t return_value = 0;
	se3_key k, *key_array = NULL;
	int i = 0, name_len = 0;
	uint8_t key_name[SE3_KEY_NAME_MAX];
	uint16_t count = 0, orig_count = 0;
	se3_session s;

	current_time = (uint32_t)time(0)+365*24*60;
	return_value = L1_login(&s, dev, USER_PIN, SE3_ACCESS_USER);	//Login as User with new pin
	assert(!return_value);
	k.data = (uint8_t*)malloc(32 * sizeof(uint8_t));
	memcpy(k.data, test_key, 32);
	
	/*Insert keys until it fails*/
	do{
		k.id = i;
		//memcpy(k.data, test_key, 32);
		k.data_size = 32;
		name_len = sprintf(k.name, "key%d", i++);
		k.name_size = name_len;
		k.validity = current_time;
		(*((uint32_t*)k.data))++;
	} while (L1_key_edit(&s, SE3_KEY_OP_INSERT, &k) == SE3_OK);

	i--;	//Number of effective inserted keys
	key_array = (se3_key*)malloc(i*sizeof(se3_key));
	assert(key_array != NULL);
	return_value = L1_key_list(&s, 0, i, NULL, key_array, &count);
	assert(!return_value);

	/*Verify that keys are correct*/
	for (i = 0; i < count; i++){
		name_len = sprintf(key_name, "key%d", i);
		if (key_array[i].id != i ||
			key_array[i].data_size != 32 ||
			key_array[i].validity != current_time ||
			name_len != key_array[i].name_size ||
			memcmp(key_name, key_array[i].name, name_len)){
			//error
			assert(0);
			break;
		}
	}

	orig_count = count; //Now we know for sure that count is the max number of keys

	/*Delete last KEY_TO_DELETE keys*/
	for (i = count - 1; i >= count - KEY_TO_DELETE; i--){
		k.id = i;
		return_value = L1_key_edit(&s, SE3_KEY_OP_DELETE, &k);
		assert(!return_value);
	}


	/*Verify keys are correctly deleted*/
	return_value = L1_key_list(&s, 0, count, NULL, key_array, &count);
	assert(!return_value);

	for (i = 0; i < count; i++){
		name_len = sprintf(key_name, "key%d", i);
		if (key_array[i].id != i ||
			key_array[i].data_size != 32 ||
			key_array[i].validity != current_time ||
			name_len != key_array[i].name_size ||
			memcmp(key_name, key_array[i].name, name_len)){
			//error
			assert(0);
			break;
		}
	}
	/*Insert back KEY_TO_DELETE keys*/
	i = count;
	do {
		k.id = i;
		memcpy(k.data, test_key, 32);
		k.data_size = 32;
		name_len = sprintf(k.name, "key%d", i++);
		k.name_size = name_len;
		k.validity = current_time;
	} while (L1_key_edit(&s, SE3_KEY_OP_INSERT, &k) == SE3_OK);
	assert((i - 1) == count + KEY_TO_DELETE);
	i--;

	/*Verify that keys are correctly inserted*/
	return_value = L1_key_list(&s, count, KEY_TO_DELETE, NULL, key_array, &count);
	assert(!return_value);
	for (i = 0; i < count; i++){
		name_len = sprintf(key_name, "key%d", i + (orig_count - KEY_TO_DELETE));
		if (key_array[i].id != i + (orig_count - KEY_TO_DELETE) ||
			key_array[i].data_size != 32 ||
			key_array[i].validity != current_time ||
			name_len != key_array[i].name_size ||
			memcmp(key_name, key_array[i].name, name_len)){
			//error
			assert(0);
			break;
		}
	}

	free(key_array);
	free(k.data);

	return_value = L1_logout(&s);									//Logout
	assert(!return_value);
	return return_value;
}

uint16_t test_crypt(se3_device *dev)
{
	int32_t return_value = SE3_OK;
	size_t dataout_len = 0;
	uint32_t sess_id = 0;
	uint8_t data1[DATA1_LEN+32], data2[DATA2_LEN], data_out[DATAOUT_LEN+32];
	uint8_t data_B5_out[DATAOUT_LEN];
	uint8_t digest1[32], digest2[32];

	memset(data1, 0, DATA1_LEN);
	memset(digest1, 0, 32);
	memset(digest2, 0, 32);
	se3_session s;
	return_value = L1_login(&s, dev, USER_PIN, SE3_ACCESS_USER);	//Login as User with new pin
	assert(!return_value);

	return_value = L1_crypto_set_time(&s, (uint32_t)time(0));
	assert(!return_value);

	/*CRYPT NOSTRA*/
	return_value = L1_encrypt(&s, SE3_ALGO_AES_HMAC, SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, 0, DATA1_LEN, data1, &dataout_len, data_out);
	assert(!return_value);
	/*CRYPT B5*/
	B5_tAesCtx ctx;
	uint8_t encrypt_key[32];
	memcpy(encrypt_key, test_key, 32);
	(*((uint32_t*)encrypt_key))++;
	return_value = B5_Aes256_Init(&ctx, encrypt_key, 32, B5_AES256_ECB_ENC);
	assert(!return_value);
	return_value = B5_Aes256_Update(&ctx, data_B5_out, data1, (DATA1_LEN / B5_AES_BLK_SIZE));
	assert(!return_value);
	return_value = B5_Aes256_Finit(&ctx);
	assert(!return_value);
	/*CONFRONTO CIPHER*/
	assert(!memcmp(data_out, data_B5_out, DATAOUT_LEN));
	/*DECRYPT NOSTRA*/
	return_value = L1_decrypt(&s, SE3_ALGO_AES_HMAC, SE3_DIR_DECRYPT | SE3_FEEDBACK_ECB, 0, DATA1_LEN, data_out, &dataout_len, data2);
	assert(!return_value);
	/*CONFRONTO CIPHER VS CLEAR*/
	assert(!memcmp(data1, data2, DATA1_LEN));
	/*DIGEST NOSTRA*/
	return_value = L1_digest(&s, SE3_ALGO_SHA256, DATA1_LEN, data1, &dataout_len, digest1);
	assert(!return_value);
	/*DIGEST B5*/
	B5_tSha256Ctx shaCtx;
	return_value = B5_Sha256_Init(&shaCtx);
	assert(!return_value);
	return_value = B5_Sha256_Update(&shaCtx, data1, DATAOUT_LEN);
	assert(!return_value);
	return_value = B5_Sha256_Finit(&shaCtx, digest2);
	assert(!return_value);
	/*CONFRONTO DIGEST*/
	assert(!memcmp(digest1, digest2, 32));

	/*HMAC DEVICE*/
	//return_value = L1_encrypt(&s, SE3_ALGO_SHA256HMAC, 0, 0, DATA1_LEN, data1, &dataout_len, digest1);
	return_value = L1_digest(&s, SE3_ALGO_HMACSHA256, DATA1_LEN, data1, &dataout_len, digest1);
	assert(!return_value);
	/*HMAC HOST*/
	B5_tHmacSha256Ctx hmacCtx;
	return_value = B5_HmacSha256_Init(&hmacCtx, encrypt_key, 32);
	assert(!return_value);
	return_value = B5_HmacSha256_Update(&hmacCtx, data1, DATA1_LEN);
	assert(!return_value);
	return_value = B5_HmacSha256_Finit(&hmacCtx, digest2);
	assert(!return_value);
	/*CONFRONTO*/
	assert(!memcmp(digest1, digest2, 32));
	return_value = L1_logout(&s);									//Logout
	assert(!return_value);

	return return_value;
}

#define BUFFER_SIZE 16

uint16_t test_session(se3_device *dev)
{
	uint16_t return_value = SE3_OK;
	se3_session s;
	
	return_value = L1_login(&s, dev, USER_PIN, SE3_ACCESS_USER);	//Login as User with new pin
	assert(!return_value);

	return_value = L1_crypto_set_time(&s, (uint32_t)time(0));
	assert(!return_value);

	uint8_t data_in[BUFFER_SIZE], data_out[BUFFER_SIZE];
	uint8_t data_B5_out[BUFFER_SIZE];
	
	se3c_rand(BUFFER_SIZE, data_in);
	memset(data_out, 0, BUFFER_SIZE);
	memset(data_B5_out, 0, BUFFER_SIZE);
	/*init aes fino a fallimento (diverse key)*/
	uint32_t i = 0, sess_array[150];
	uint32_t max_session = 0;
	uint16_t dataout_len = 0;
	while ((return_value = L1_crypto_init(&s, SE3_ALGO_AES, SE3_DIR_ENCRYPT | SE3_FEEDBACK_ECB, i, &sess_array[i])) == SE3_OK){
		i++;
	}
	assert(return_value == SE3_ERR_MEMORY);
	max_session = i - 1;
	/*update aes per verifica*/
	B5_tAesCtx ctx;
	se3_key k;
	int name_len = 0;
	k.data = (uint8_t*)malloc(32 * sizeof(uint8_t));
	assert(k.data != NULL);
	memcpy(k.data, test_key, 32);
	for (i = 0; i < max_session; i++){
		return_value = L1_crypto_update(&s,
			sess_array[i],
			0,
			0,
			NULL,
			BUFFER_SIZE,
			data_in,
			&dataout_len,
			data_out);
		assert(!return_value);

		(*((uint32_t*)k.data))++;

		return_value = B5_Aes256_Init(&ctx, k.data, 32, B5_AES256_ECB_ENC);
		assert(!return_value);
		
		return_value = B5_Aes256_Update(&ctx, data_B5_out, data_in, (BUFFER_SIZE/ B5_AES_BLK_SIZE));
		assert(!return_value);

		assert(!memcmp(data_out, data_B5_out, BUFFER_SIZE)); 
	}
	/*finit aes metà sessioni*/
	for (i = 1; i < max_session; i += 2){
		return_value = L1_crypto_update(&s,
			sess_array[i],
			SE3_CRYPTO_FLAG_FINIT,
			0,
			NULL,
			0,
			NULL,
			NULL,
			NULL);
		assert(!return_value);
	}
	/*init sha*/
	uint32_t sha_sess[10];
	for (i = 0; i < 10; i++){
		return_value = L1_crypto_init(&s, SE3_ALGO_SHA256, 0, 0, &sha_sess[i]);
		assert(!return_value || return_value==SE3_ERR_MEMORY);
	}
	
	/*update aes disponibili per verifica*/
	memcpy(k.data, test_key, 32);
	(*((uint32_t*)k.data))++;

	for (i = 0; i < max_session; i+=2){
		return_value = L1_crypto_update(&s,
			sess_array[i],
			0,
			0,
			NULL,
			BUFFER_SIZE,
			data_in,
			&dataout_len,
			data_out);
		assert(!return_value);

		return_value = B5_Aes256_Init(&ctx, k.data, 32, B5_AES256_ECB_ENC);
		assert(!return_value);

		return_value = B5_Aes256_Update(&ctx, data_B5_out, data_in, (BUFFER_SIZE / B5_AES_BLK_SIZE));
		assert(!return_value);

		assert(!memcmp(data_out, data_B5_out, BUFFER_SIZE));
		(*((uint32_t*)k.data)) += 2;
	}
	/*update sha per verifica*/
	uint8_t sha1[32], sha2[32];
	B5_tSha256Ctx shaCtx;
	for (i = 0; i < 10; i++){
		return_value = L1_crypto_update(&s, sha_sess[i], SE3_CRYPTO_FLAG_FINIT, BUFFER_SIZE, data_in, 0, NULL, NULL, sha1);
		assert(!return_value);

		return_value = B5_Sha256_Init(&shaCtx);
		assert(!return_value);
		return_value = B5_Sha256_Update(&shaCtx, data_in, BUFFER_SIZE);
		assert(!return_value);
		return_value = B5_Sha256_Finit(&shaCtx, sha2);
		assert(!return_value);

		assert(!memcmp(sha1, sha2, 32));
	}
	free(k.data);

	return_value = L1_logout(&s);									//Logout
	assert(!return_value);

	return return_value;
}

#define MAX_ALG 10
uint16_t test_algorithm(se3_device *dev)
{
	uint16_t return_value = SE3_OK, count = 0;
	se3_session s;
	se3_algo alg_array[MAX_ALG];
	int i = 0;
	return_value = L1_login(&s, dev, USER_PIN, SE3_ACCESS_USER);	//Login as User with new pin
	assert(!return_value);

	return_value = L1_get_algorithms(&s, 0, MAX_ALG, alg_array, &count);
	assert(!return_value);

	char buff_name[SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE+1];
	buff_name[SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE] = 0;
	
	for (i = 0; i < count; i++){
		memcpy(buff_name, alg_array[i].name, SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE);
		printf("alg name: %s\n", buff_name);
		printf("alg type %u\n", (unsigned int)alg_array[i].type);
		printf("alg block_size %u\n", (unsigned int)alg_array[i].block_size);
		printf("alg key_size %u\n\n\n", (unsigned int)alg_array[i].key_size);
	}

	return_value = L1_logout(&s);									//Logout
	assert(!return_value);

	return return_value;
}

uint16_t test_AesHmacSha256s(se3_device *dev)
{
	uint16_t return_value = SE3_OK, count = 0;
	se3_session s;
	uint32_t sid = SE3_SESSION_INVALID;
	int i = 0;
	uint16_t dataout_len = 0;

	enum {
		TEST_SIZE = 64,
		NONCE_SIZE = 32
	};
	
	uint8_t iv[B5_AES_IV_SIZE];
	uint8_t nonce[NONCE_SIZE];
	uint8_t* buf = (uint8_t*)malloc(TEST_SIZE);
	uint8_t* buf_enc = (uint8_t*)malloc(TEST_SIZE + B5_SHA256_DIGEST_SIZE);
	uint8_t* buf_dec = (uint8_t*)malloc(TEST_SIZE + B5_SHA256_DIGEST_SIZE);


	se3c_rand(TEST_SIZE, buf);
	se3c_rand(B5_AES_IV_SIZE, iv);
	se3c_rand(NONCE_SIZE, nonce);
	
	return_value = L1_login(&s, dev, USER_PIN, SE3_ACCESS_USER);	//Login as User with new pin
	assert(!return_value);
	
	return_value = L1_crypto_set_time(&s, (uint32_t)time(0));
	assert(!return_value);

	return_value = L1_crypto_init(&s, 3, SE3_DIR_ENCRYPT | SE3_FEEDBACK_CBC, 1, &sid);
	assert(!return_value);

	return_value = L1_crypto_update(&s, sid, SE3_CRYPTO_FLAG_SETNONCE, NONCE_SIZE, test_key, 0, NULL, &dataout_len, NULL);
	assert(!return_value);
	assert(dataout_len == 0);

	return_value = L1_crypto_update(&s, sid, 
		SE3_CRYPTO_FLAG_RESET | SE3_CRYPTO_FLAG_AUTH | SE3_CRYPTO_FLAG_FINIT, 
		B5_AES_IV_SIZE, test_key, TEST_SIZE, buf, &dataout_len, buf_enc);
	assert(!return_value);
	assert(dataout_len == TEST_SIZE + B5_SHA256_DIGEST_SIZE);

	return_value = L1_crypto_init(&s, 3, SE3_DIR_DECRYPT | SE3_FEEDBACK_CBC, 1, &sid);
	assert(!return_value);

	return_value = L1_crypto_update(&s, sid, SE3_CRYPTO_FLAG_SETNONCE, NONCE_SIZE, test_key, 0, NULL, &dataout_len, NULL);
	assert(!return_value);
	assert(dataout_len == 0);

	return_value = L1_crypto_update(&s, sid,
		SE3_CRYPTO_FLAG_RESET | SE3_CRYPTO_FLAG_AUTH | SE3_CRYPTO_FLAG_FINIT,
		B5_AES_IV_SIZE, test_key, TEST_SIZE, buf_enc, &dataout_len, buf_dec);
	assert(!return_value);
	assert(dataout_len == TEST_SIZE + B5_SHA256_DIGEST_SIZE);
	
	assert(!memcmp(buf, buf_dec, TEST_SIZE));
	assert(!memcmp(buf_enc + TEST_SIZE, buf_dec + TEST_SIZE, B5_SHA256_DIGEST_SIZE));

	free(buf);
	free(buf_enc);
	free(buf_dec);

	return_value = L1_logout(&s);									//Logout
	assert(!return_value);


	return return_value;
}

void main_tests()
{
	uint16_t return_value = 0;
	se3_device dev;
	
#ifndef CUBESIM
	se3_disco_it it;
	L0_discover_init(&it);
	if (L0_discover_next(&it)){
		return_value = L0_open(&dev, &(it.device_info), SE3_TIMEOUT);
	}
	assert(!return_value);
#else
	return_value = L0_open_sim(&dev);
	assert(return_value == SE3_OK);
#endif
	return_value = L0_factoryinit(&dev, serialno);
	assert(!return_value);

	return_value = test_login(&dev);
	assert(!return_value);
	
	return_value = test_keys(&dev);
	assert(!return_value);

	return_value = test_crypt(&dev);
	assert(!return_value);

	return_value = test_session(&dev);
	assert(!return_value);
	
	return_value = test_session(&dev);
	assert(!return_value);

	return_value = test_AesHmacSha256s(&dev);
	assert(!return_value);

	return_value = test_algorithm(&dev);
	assert(!return_value);
}

int main()
{
    sim_init();
    sim_clear_flash();
	sim_start();

	main_tests();
	getchar();
	return 0;
}
