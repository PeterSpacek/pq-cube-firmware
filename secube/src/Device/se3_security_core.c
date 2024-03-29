/**
 *  \file se3_security_core.c
 *  \author Nicola Ferri
 *  \co-author Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia, Peter Spacek
 *  \brief Security core
 */

#include "se3_security_core.h"
#include "se3_flash.h"
#include "se3_algo_Aes.h"
#include "se3_algo_sha256.h"
#include "se3_algo_HmacSha256.h"
#include "se3_algo_AesHmacSha256s.h"
#include "se3_algo_aes256hmacsha256.h"

#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/kyber1024/kyber_api.h"
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/kyber1024-m4/kyber_m4_api.h"
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/kyber1024-m4-protected/kyber_m4_api_prot.h"

#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/ntruhps4096821/ntruhps4096821_api.h"
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/ntruhps4096821-m4/ntruhps4096821_m4_api.h"

#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/firesaber/firesaber_api.h"
#include "../../../ws/secubedevboard/Application/src/Device/pq-crypto/crypto_kem/saber-m4/saber_m4_api.h"

uint32_t m_nStart;               //DEBUG Stopwatch start cycle counter value
uint32_t m_nStop;                //DEBUG Stopwatch stop cycle counter value

se3_kem_descriptor kem_table[SE3_KEM_ALGO_MAX] = {
		{ ///< CRYSTALS-KYBER
			KYBER1024_M4_crypto_kem_keypair_prot,
			KYBER1024_M4_crypto_kem_enc_prot,
			KYBER1024_M4_crypto_kem_dec_prot,
			KYBER1024_M4_CRYPTO_ALGNAME_prot,
			SE3_CRYPTO_TYPE_KEM,
			KYBER1024_M4_CRYPTO_BYTES_prot,
			KYBER1024_M4_CRYPTO_CIPHERTEXTBYTES_prot,
			KYBER1024_M4_CRYPTO_PUBLICKEYBYTES_prot,
			KYBER1024_M4_CRYPTO_SECRETKEYBYTES_prot
		},
		{ ///< CRYSTALS-KYBER
			PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair,
			PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc,
			PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
			PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES
		},
		{ ///< CRYSTALS-KYBER
			KYBER1024_M4_crypto_kem_keypair,
			KYBER1024_M4_crypto_kem_enc,
			KYBER1024_M4_crypto_kem_dec,
			KYBER1024_M4_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			KYBER1024_M4_CRYPTO_BYTES,
			KYBER1024_M4_CRYPTO_CIPHERTEXTBYTES,
			KYBER1024_M4_CRYPTO_PUBLICKEYBYTES,
			KYBER1024_M4_CRYPTO_SECRETKEYBYTES
		},
		{ ///< NTRU
			PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair,
			PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_enc,
			PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_BYTES,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_CIPHERTEXTBYTES,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_PUBLICKEYBYTES,
			PQCLEAN_NTRUHPS4096821_CLEAN_CRYPTO_SECRETKEYBYTES
		},
		{ ///< NTRU
			NTRUHPS4096821_M4_crypto_kem_keypair,
			NTRUHPS4096821_M4_crypto_kem_enc,
			NTRUHPS4096821_M4_crypto_kem_dec,
			NTRUHPS4096821_M4_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			NTRUHPS4096821_M4_CRYPTO_BYTES,
			NTRUHPS4096821_M4_CRYPTO_CIPHERTEXTBYTES,
			NTRUHPS4096821_M4_CRYPTO_PUBLICKEYBYTES,
			NTRUHPS4096821_M4_CRYPTO_SECRETKEYBYTES
		},
		{ ///< FIRESABER
			PQCLEAN_FIRESABER_CLEAN_crypto_kem_keypair,
			PQCLEAN_FIRESABER_CLEAN_crypto_kem_enc,
			PQCLEAN_FIRESABER_CLEAN_crypto_kem_dec,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_BYTES,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_CIPHERTEXTBYTES,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_PUBLICKEYBYTES,
			PQCLEAN_FIRESABER_CLEAN_CRYPTO_SECRETKEYBYTES
		},
		{ ///< FIRESABER
			SABER_M4_crypto_kem_keypair,
			SABER_M4_crypto_kem_enc,
			SABER_M4_crypto_kem_dec,
			SABER_M4_CRYPTO_ALGNAME,
			SE3_CRYPTO_TYPE_KEM,
			SABER_M4_CRYPTO_BYTES,
			SABER_M4_CRYPTO_CIPHERTEXTBYTES,
			SABER_M4_CRYPTO_PUBLICKEYBYTES,
			SABER_M4_CRYPTO_SECRETKEYBYTES
		},
		{ NULL, NULL, NULL, "", 0, 0, 0, 0 }
	};

/* Cryptographic algorithms handlers and display info for the security core ONLY. */
se3_algo_descriptor algo_table[SE3_ALGO_MAX] = {
	{
		se3_algo_Aes_init,
		se3_algo_Aes_update,
		sizeof(B5_tAesCtx),
		"Aes",
		SE3_CRYPTO_TYPE_BLOCKCIPHER,
		B5_AES_BLK_SIZE,
		B5_AES_256 },
	{
		se3_algo_Sha256_init,
		se3_algo_Sha256_update,
		sizeof(B5_tSha256Ctx),
		"Sha256",
		SE3_CRYPTO_TYPE_DIGEST,
		B5_SHA256_DIGEST_SIZE,
		0 },
	{
		se3_algo_HmacSha256_init,
		se3_algo_HmacSha256_update,
		sizeof(B5_tHmacSha256Ctx),
		"HmacSha256",
		SE3_CRYPTO_TYPE_DIGEST,
		B5_SHA256_DIGEST_SIZE,
		B5_AES_256 },
	{
		se3_algo_AesHmacSha256s_init,
		se3_algo_AesHmacSha256s_update,
		sizeof(B5_tAesCtx) + sizeof(B5_tHmacSha256Ctx) + 2 * B5_AES_256 + sizeof(uint16_t) + 3 * sizeof(uint8_t),
		"AesHmacSha256s",
		SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH,
		B5_AES_BLK_SIZE,
		B5_AES_256 },
	{
		se3_algo_aes256hmacsha256_init,
		se3_algo_aes256hmacsha256_update,
		sizeof(B5_tAesCtx) + sizeof(B5_tHmacSha256Ctx),
		"AES256HMACSHA256",
		SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH,
		B5_AES_BLK_SIZE,
		B5_AES_256 },
	{ NULL, NULL, 0, "", 0, 0, 0 },
	{ NULL, NULL, 0, "", 0, 0, 0 },
	{ NULL, NULL, 0, "", 0, 0, 0 }
};

union {
    B5_tSha256Ctx sha;
    B5_tAesCtx aes;
} ctx;

void se3_security_core_init(){
    memset(&ctx, 0, sizeof(ctx));
    memset((void*)&se3_security_info, 0, sizeof(SE3_SECURITY_INFO));
}

static bool record_find(uint16_t record_type, se3_flash_it* it)
{
    uint16_t it_record_type = 0;
    while (se3_flash_it_next(it)) {
        if (it->type == SE3_FLASH_TYPE_RECORD) {
            SE3_GET16(it->addr, SE3_RECORD_OFFSET_TYPE, it_record_type);
            if (it_record_type == record_type) {
                return true;
            }
        }
    }
    return false;
}

bool record_set(uint16_t type, const uint8_t* data)
{
    se3_flash_it it;
    bool found = false;
    se3_flash_it it2;
    uint8_t tmp[2];
    if (type >= SE3_RECORD_MAX) {
        return false;
    }
    se3_flash_it_init(&it);
    if (record_find(type, &it)) {
        found = true;
    }

    // allocate new flash block
    memcpy(&it2, &it, sizeof(se3_flash_it));
    if (!se3_flash_it_new(&it2, SE3_FLASH_TYPE_RECORD, SE3_RECORD_SIZE_TYPE + SE3_RECORD_SIZE)) {
        return false;
    }
    // write record type and data
    if (!se3_flash_it_write(&it2, SE3_RECORD_OFFSET_DATA, data, SE3_RECORD_SIZE)) {
        return false;
    }
    SE3_SET16(tmp, 0, type);
    if (!se3_flash_it_write(&it2, SE3_RECORD_OFFSET_TYPE, tmp, SE3_RECORD_SIZE_TYPE)) {
        return false;
    }

    if (found) {
        // delete previously found flash block
        if (!se3_flash_it_delete(&it)) {
            return false;
        }
    }

    return true;
}

bool record_get(uint16_t type, uint8_t* data)
{
    se3_flash_it it;
    if (type >= SE3_RECORD_MAX) {
        return false;
    }
    se3_flash_it_init(&it);
    if (!record_find(type, &it)) {
        return false;
    }
    memcpy(data, it.addr + SE3_RECORD_OFFSET_DATA, SE3_RECORD_SIZE);
    return true;
}

char* concat(char *s1, char *s2)
{
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    char *result = malloc(len1+len2+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
    memcpy(result, s1, len1);
    memcpy(result+len1, s2, len2+1);//+1 to copy the null-terminator
    return result;
}


static inline void stopwatch_reset(void)
{
    /* Enable DWT */
    DEMCR |= DEMCR_TRCENA;
    *DWT_CYCCNT = 0;
    /* Enable CPU cycle counter */
    DWT_CTRL |= CYCCNTENA;
}

uint16_t test_implementations_get_data(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{

    struct {
        uint32_t num_of_alg;
    } resp_params;

    uint32_t status,var;

    if (*(req+SE3_CMD1_TEST_IMPLEMENTATIONS_REQ) != SE3_OK) {
        return SE3_ERR_PARAMS;
    }

    *resp_size=4;

    resp_params.num_of_alg=SE3_KEM_ALGO_MAX;
    SE3_SET32(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO,  resp_params.num_of_alg);

    se3_flash_key key;
    se3_flash_it it = { .addr = NULL };

    key.id = TEST_ID;
    key.data=malloc(SE3_KEM_ALGO_MAX*3*sizeof(uint32_t));

    se3_flash_it_init(&it);
    if (!se3_key_find(key.id, &it)) {
    	            it.addr = NULL;
    	            SE3_TRACE(("[crypto_kem_dec] key not found\n"));
    	            return SE3_ERR_RESOURCE;
    	        }
   se3_key_read(&it, &key);


    uint64_t * data;
    data=(uint64_t *)key.data;

    for (var = 1; var < SE3_KEM_ALGO_MAX-1; var++) {
        SE3_SET32(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + (*resp_size), var);
        (*resp_size)+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_ID_SIZE;
        memcpy(resp + SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + (*resp_size),  kem_table[var].display_name, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_NAME_SIZE);
        (*resp_size)+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_NAME_SIZE;


        SE3_SET64(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + (*resp_size), data[var*3+0]);
        (*resp_size)+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_TIMER_SIZE;

        SE3_SET64(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + (*resp_size), data[var*3+1]);
        (*resp_size)+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_TIMER_SIZE;

        SE3_SET64(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + (*resp_size), data[var*3+2]);
        (*resp_size)+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_TIMER_SIZE;

	}
    free(key.data);
	return SE3_OK;
}

uint16_t test_implementations_write_data(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint32_t num_of_alg;
    } resp_params;

    uint32_t status,var;

    if (*(req+SE3_CMD1_TEST_IMPLEMENTATIONS_REQ) != SE3_OK) {
        return SE3_ERR_PARAMS;
    }

    *resp_size=4;
    resp_params.num_of_alg=SE3_KEM_ALGO_MAX;
    SE3_SET32(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO,  resp_params.num_of_alg);

    uint32_t max_ciphertext_size;
    uint32_t max_public_key_size;
    uint32_t max_secret_key_size;
    uint32_t max_size;
    max_sizes(&max_ciphertext_size,&max_public_key_size,&max_secret_key_size,&max_size);

    uint8_t* ciphertext= malloc(max_ciphertext_size);
    uint8_t* public_key= malloc(max_public_key_size);
    uint8_t* secret_key= malloc(max_secret_key_size);
    uint8_t* symmetric_key= malloc(max_size);
    uint8_t* symmetric_key2= malloc(max_size);

    uint32_t timer;

    for (var = 0; var < SE3_KEM_ALGO_MAX-1; var++) {
        SE3_SET32(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + *resp_size, var);
        *resp_size+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_ID_SIZE;
        memcpy(resp + SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + *resp_size,  kem_table[var].display_name, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_NAME_SIZE);
        *resp_size+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_NAME_SIZE;

    	timer=0;
        for(int i =0;i<NUM_OF_TESTS;i++){
			stopwatch_reset();
			__disable_irq();
			STOPWATCH_START;
			status = kem_table[var].keypair(public_key,secret_key);
			STOPWATCH_STOP;
			__enable_irq();
			timer += m_nStop - m_nStart;
	        if (SE3_OK != status) {
	            free(ciphertext);
	            free(public_key);
	            free(secret_key);
	            free(symmetric_key);
	            free(symmetric_key2);
	            return status;
	        }
        }
        timer/=NUM_OF_TESTS;


        SE3_SET32(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + *resp_size, timer);
        *resp_size+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_TIMER_SIZE;

    	timer=0;
        for(int i =0;i<NUM_OF_TESTS;i++){
			stopwatch_reset();
			//__disable_irq();
			STOPWATCH_START;
			status = kem_table[var].enc(ciphertext, symmetric_key, public_key);
			STOPWATCH_STOP;
			//__enable_irq();
			timer += m_nStop - m_nStart;
	        if (SE3_OK != status) {
	            free(ciphertext);
	            free(public_key);
	            free(secret_key);
	            free(symmetric_key);
	            free(symmetric_key2);
	        }
		}
		timer/=NUM_OF_TESTS;

        SE3_SET32(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + *resp_size, timer);
        *resp_size+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_TIMER_SIZE;

    	timer=0;
        for(int i =0;i<NUM_OF_TESTS;i++){
			stopwatch_reset();
			//__disable_irq();
			STOPWATCH_START;
			status = kem_table[var].dec(symmetric_key2, ciphertext, secret_key);
			STOPWATCH_STOP;
			//__enable_irq();
			timer += m_nStop - m_nStart;
	        if (SE3_OK != status) {
	            free(ciphertext);
	            free(public_key);
	            free(secret_key);
	            free(symmetric_key);
	            free(symmetric_key2);
	            return status;
	        }
		}
		timer/=NUM_OF_TESTS;

        SE3_SET32(resp, SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_NUM_OF_ALGO + *resp_size, timer);
        *resp_size+=SE3_CMD1_TEST_IMPLEMENTATIONS_RESP_ALGO_TIMER_SIZE;

    	/* Compare plain data with decrypted data */
    	if (memcmp(symmetric_key, symmetric_key2, kem_table[var].display_size)!= 0) {
            return SE3_ERR_STATE;
    	}
	}

    free(ciphertext);
    free(public_key);
    free(secret_key);
    free(symmetric_key);
    free(symmetric_key2);
	return status;
}

uint16_t crypto_kem_keypair(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t algo;
        uint32_t key_valid;
        uint32_t sk_id;
    } req_params;
    struct {
        uint32_t pk_len;
        uint8_t* pk;
    } resp_params;

    se3_flash_key sk;
    se3_flash_key pk;
    se3_flash_it it = { .addr = NULL };
    se3_crypto_kem_keypair_handler handler = NULL;
    uint32_t status;

    if (req_size != SE3_CMD1_CRYPTO_KEM_KEYPAIR_REQ_SIZE) {
        SE3_TRACE(("[crypto_kem_keypair] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

    SE3_GET16(req, SE3_CMD1_CRYPTO_KEM_KEYPAIR_REQ_OFF_ALGORITHM, req_params.algo);
    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_KEYPAIR_REQ_OFF_KEY_VALID, req_params.key_valid);
    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_KEYPAIR_REQ_OFF_SK_ID, req_params.sk_id);

    if (req_params.algo < SE3_KEM_ALGO_MAX) {
        handler = kem_table[req_params.algo].keypair;
    }
    if (handler == NULL) {
        SE3_TRACE(("[crypto_kem_keypair] algo not found\n"));
        return SE3_ERR_PARAMS;
    }

    pk.data=resp+SE3_CMD1_CRYPTO_KEM_KEYPAIR_RESP_OFF_PK_DATA;
    sk.data=malloc(kem_table[req_params.algo].display_secret_key_size);
    status = handler(pk.data, sk.data);

	pk.data_size=kem_table[req_params.algo].display_public_key_size;
	sk.data_size=kem_table[req_params.algo].display_secret_key_size;
	pk.name = concat(kem_table[req_params.algo].display_name, ", public key");
	sk.name = concat(kem_table[req_params.algo].display_name, ", secret key");
    pk.id = SE3_KEYPAIR_ID_OFFSET  + 2 * req_params.sk_id + 1;
    sk.id = SE3_KEYPAIR_ID_OFFSET  + 2 * req_params.sk_id;
    pk.validity = req_params.key_valid;
    sk.validity = req_params.key_valid;
    pk.name_size = strlen(pk.name);
    sk.name_size = strlen(sk.name);

    if (pk.id == SE3_KEY_INVALID) {
        memset(pk.data, 0, SE3_KEY_DATA_MAX);
        memset(sk.data, 0, SE3_KEY_DATA_MAX);
    }

    else {
        se3_flash_it_init(&it);
        if (!se3_key_find(pk.id, &it)) {
            it.addr = NULL;
        }
        else {
    		if (!se3_flash_it_delete(&it))
    			return SE3_ERR_HW;
    		it.addr = NULL;
        }
        if (!se3_key_new(&it, &pk)) {
            SE3_TRACE(("[crypto_kem_keypair] pk se3_key_new failed\n"));
            return SE3_ERR_MEMORY;
        }
        if (!se3_key_find(sk.id, &it)) {
            it.addr = NULL;
        }
        else{
    		if (!se3_flash_it_delete(&it))
    			return SE3_ERR_HW;
    		it.addr = NULL;
        }
        if (!se3_key_new(&it, &sk)) {
            SE3_TRACE(("[crypto_kem_keypair] sk se3_key_new failed\n"));
            return SE3_ERR_MEMORY;
        }
    }

    SE3_SET16(resp, SE3_CMD1_CRYPTO_KEM_KEYPAIR_RESP_OFF_PK_LEN, pk.data_size);
    *resp_size = SE3_CMD1_CRYPTO_KEM_KEYPAIR_RESP_OFF_PK_DATA+pk.data_size;
    free(sk.data);
    free(sk.name);
    free(pk.name);

	return status;
}


uint16_t derive_and_store_keys(se3_flash_key * pms,
		uint8_t salt_len,
		const uint8_t* salt,
		uint32_t ms_id,
		uint32_t cs_id,
		uint32_t ss_id,
		uint32_t validity,
		uint16_t algo){

    se3_flash_it it = { .addr = NULL };
    se3_flash_key ms;
    se3_flash_key cs;
    se3_flash_key ss;
	ms.name = concat(kem_table[algo].display_name, ", master secret");
	cs.name = concat(kem_table[algo].display_name, ", client secret");
	ss.name = concat(kem_table[algo].display_name, ", server secret");
    ms.id =  ms_id;
    cs.id =  cs_id;
    ss.id =  ss_id;
    ss.validity = validity;
    cs.validity = validity;
    ms.validity = validity;
    ss.name_size = strlen(ss.name);
    cs.name_size = strlen(cs.name);
    ms.name_size = strlen(ms.name);
    ms.data_size=48;
    cs.data_size=32;
    ss.data_size=32;
    ms.data=malloc(ms.data_size);
    cs.data=malloc(cs.data_size);
    ss.data=malloc(ss.data_size);

	PBKDF2HmacSha256(pms->data, pms->data_size, salt, salt_len, 100, ms.data, ms.data_size);
	PBKDF2HmacSha256(ms.data, ms.data_size, salt, salt_len, 100, cs.data, cs.data_size);
	PBKDF2HmacSha256(ms.data, ms.data_size, salt, salt_len, 100, ss.data, ss.data_size);

    if (ms.id == SE3_KEY_INVALID) {
        memset(ms.data, 0, SE3_KEY_DATA_MAX);
        memset(ss.data, 0, SE3_KEY_DATA_MAX);
        memset(cs.data, 0, SE3_KEY_DATA_MAX);
    }


    else {
        se3_flash_it_init(&it);
        if (!se3_key_find(ms.id, &it)) {
            it.addr = NULL;
        }
        else {
    		if (!se3_flash_it_delete(&it))
    			return SE3_ERR_HW;
    		it.addr = NULL;
        }
        if (!se3_key_new(&it, &ms)) {
            SE3_TRACE(("[derive and store keys] mk se3_key_new failed\n"));
            return SE3_ERR_MEMORY;
        }
        if (!se3_key_find(cs.id, &it)) {
            it.addr = NULL;
        }
        else{
    		if (!se3_flash_it_delete(&it))
    			return SE3_ERR_HW;
    		it.addr = NULL;
        }
        if (!se3_key_new(&it, &cs)) {
            SE3_TRACE(("[derive and store keys] ck se3_key_new failed\n"));
            return SE3_ERR_MEMORY;
        }
        if (!se3_key_find(ss.id, &it)) {
            it.addr = NULL;
        }
        else{
    		if (!se3_flash_it_delete(&it))
    			return SE3_ERR_HW;
    		it.addr = NULL;
        }
        if (!se3_key_new(&it, &ss)) {
            SE3_TRACE(("[derive and store keys] sk se3_key_new failed\n"));
            return SE3_ERR_MEMORY;
        }
    }

}

uint16_t crypto_kem_enc(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
    struct {
        uint16_t algo;
        uint32_t pk_len;
        const uint8_t* pk;
        uint32_t validity;
        uint32_t ms_id;
        uint32_t cs_id;
        uint32_t ss_id;
        const uint8_t* crsr;
    } req_params;
    struct {
        uint32_t ct_len;
        uint8_t* ct;

    } resp_params;

    se3_crypto_kem_enc_handler handler = NULL;
    uint32_t status;

    if (req_size < SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_PK_DATA) {
        SE3_TRACE(("[crypto_kem_enc] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

    SE3_GET16(req, SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_ALGORITHM, req_params.algo);
    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_PK_LEN, req_params.pk_len);
    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_VAL, req_params.validity);
    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_MS_ID, req_params.ms_id);
    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_CS_ID, req_params.cs_id);
    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_SS_ID, req_params.ss_id);
    req_params.crsr = req + SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_CRSR_DATA;
    req_params.pk = req + SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_PK_DATA;

    if (req_params.algo < SE3_KEM_ALGO_MAX) {
        handler = kem_table[req_params.algo].enc;
    }
    if (handler == NULL) {
        SE3_TRACE(("[crypto_kem_enc] algo not found\n"));
        return SE3_ERR_PARAMS;
    }

	resp_params.ct_len=kem_table[req_params.algo].display_ciphertext_size;
	resp_params.ct=resp+SE3_CMD1_CRYPTO_KEM_ENC_RESP_OFF_DATA;

    se3_flash_key pms;
	pms.data_size=kem_table[req_params.algo].display_size;
    pms.data=malloc(pms.data_size);
    status = handler(resp_params.ct, pms.data, req_params.pk);

    derive_and_store_keys(&pms,
    		64,
			req_params.crsr,
			req_params.ms_id,
			req_params.cs_id,
			req_params.ss_id,
			req_params.validity,
			req_params.algo);

    free(pms.data);
    SE3_SET32(resp, SE3_CMD1_CRYPTO_KEM_ENC_RESP_OFF_CT_LEN, resp_params.ct_len);
    *resp_size = SE3_CMD1_CRYPTO_KEM_ENC_RESP_OFF_DATA+resp_params.ct_len;

    return status;
}

/* Returns a secret
uint16_t crypto_kem_enc(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
    struct {
        uint16_t algo;
        uint32_t pk_len;
        const uint8_t* pk;
    } req_params;
    struct {
        uint32_t ct_len;
        uint8_t* ct;
        uint32_t ss_len;
        uint8_t* ss;
    } resp_params;

    se3_crypto_kem_enc_handler handler = NULL;
    uint32_t status;

    if (req_size < SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_PK_DATA) {
        SE3_TRACE(("[crypto_kem_enc] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

    SE3_GET16(req, SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_ALGORITHM, req_params.algo);
    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_PK_LEN, req_params.pk_len);
    req_params.pk = req + SE3_CMD1_CRYPTO_KEM_ENC_REQ_OFF_PK_DATA;


    if (req_params.algo < SE3_KEM_ALGO_MAX) {
        handler = kem_table[req_params.algo].enc;
    }
    if (handler == NULL) {
        SE3_TRACE(("[crypto_kem_enc] algo not found\n"));
        return SE3_ERR_PARAMS;
    }

	resp_params.ct_len=kem_table[req_params.algo].display_ciphertext_size;
	resp_params.ss_len=kem_table[req_params.algo].display_size;
	resp_params.ct=resp+SE3_CMD1_CRYPTO_KEM_ENC_RESP_OFF_DATA;
	resp_params.ss=resp+SE3_CMD1_CRYPTO_KEM_ENC_RESP_OFF_DATA+resp_params.ct_len;

    status = handler(resp_params.ct, resp_params.ss, req_params.pk);

    SE3_SET32(resp, SE3_CMD1_CRYPTO_KEM_ENC_RESP_OFF_CT_LEN, resp_params.ct_len);
    SE3_SET32(resp, SE3_CMD1_CRYPTO_KEM_ENC_RESP_OFF_SS_LEN, resp_params.ss_len);

    *resp_size = SE3_CMD1_CRYPTO_KEM_ENC_RESP_OFF_DATA+resp_params.ss_len+resp_params.ct_len;

    return status;
}

uint16_t crypto_kem_dec(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	struct {
	        uint16_t algo;
	        uint32_t sk_id;
	        uint32_t ct_len;
	        const uint8_t* ct;
	    } req_params;
	    struct {
	        uint32_t ss_len;
	        uint8_t* ss;
	    } resp_params;

	    se3_crypto_kem_enc_handler handler = NULL;
	    uint32_t status;

	    if (req_size < SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_CT_DATA) {
	        SE3_TRACE(("[crypto_kem_dec] req size mismatch\n"));
	        return SE3_ERR_PARAMS;
	    }

	    SE3_GET16(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_ALGORITHM, req_params.algo);
	    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_SK_ID, req_params.sk_id);
	    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_CT_LEN, req_params.ct_len);
	    req_params.ct = req + SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_CT_DATA;


	    if (req_params.algo < SE3_KEM_ALGO_MAX) {
	        handler = kem_table[req_params.algo].dec;
	    }
	    if (handler == NULL) {
	        SE3_TRACE(("[crypto_kem_dec] algo not found\n"));
	        return SE3_ERR_PARAMS;
	    }

		resp_params.ss_len=kem_table[req_params.algo].display_size;
		resp_params.ss=resp+SE3_CMD1_CRYPTO_KEM_DEC_RESP_OFF_SS_DATA;


	    se3_flash_key key;
	    se3_flash_it it = { .addr = NULL };

	    key.id = SE3_KEYPAIR_ID_OFFSET  + 2 * req_params.sk_id;
	    key.data=malloc(kem_table[req_params.algo].display_secret_key_size);
	    if (key.id == SE3_KEY_INVALID) {
            SE3_TRACE(("[crypto_kem_dec] key id invalid\n"));
	        return SE3_ERR_PARAMS;
	    }
	    else {
	        se3_flash_it_init(&it);
	        if (!se3_key_find(key.id, &it)) {
	            it.addr = NULL;
	            SE3_TRACE(("[crypto_kem_dec] key not found\n"));
	            return SE3_ERR_RESOURCE;
	        }
	        se3_key_read(&it, &key);

			if (key.validity < se3_time_get() || !(get_now_initialized())) {
				SE3_TRACE(("[crypto_kem_dec] key expired\n"));
				return SE3_ERR_EXPIRED;
			}
	    }

	    status = handler(resp_params.ss, req_params.ct, key.data);

	    SE3_SET32(resp, SE3_CMD1_CRYPTO_KEM_DEC_RESP_OFF_SS_LEN, resp_params.ss_len);

	    *resp_size = SE3_CMD1_CRYPTO_KEM_DEC_RESP_OFF_SS_DATA+resp_params.ss_len;
	    free(key.data);
	    return status;
}
*/
uint16_t crypto_kem_dec(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp){
	struct {
	        uint16_t algo;
	        uint32_t sk_id;
	        uint32_t ct_len;
	        const uint8_t* ct;
	        uint32_t validity;
	        uint32_t ms_id;
	        uint32_t cs_id;
	        uint32_t ss_id;
	        const uint8_t* crsr;
	    } req_params;
	    struct {
	    } resp_params;

	    se3_crypto_kem_enc_handler handler = NULL;
	    uint32_t status;

	    if (req_size < SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_CT_DATA) {
	        SE3_TRACE(("[crypto_kem_dec] req size mismatch\n"));
	        return SE3_ERR_PARAMS;
	    }

	    SE3_GET16(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_ALGORITHM, req_params.algo);
	    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_SK_ID, req_params.sk_id);
	    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_CT_LEN, req_params.ct_len);

	    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_VAL, req_params.validity);
	    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_MS_ID, req_params.ms_id);
	    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_CS_ID, req_params.cs_id);
	    SE3_GET32(req, SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_SS_ID, req_params.ss_id);
	    req_params.crsr = req + SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_CRSR_DATA;
	    req_params.ct = req + SE3_CMD1_CRYPTO_KEM_DEC_REQ_OFF_CT_DATA;


	    if (req_params.algo < SE3_KEM_ALGO_MAX) {
	        handler = kem_table[req_params.algo].dec;
	    }
	    if (handler == NULL) {
	        SE3_TRACE(("[crypto_kem_dec] algo not found\n"));
	        return SE3_ERR_PARAMS;
	    }


	    se3_flash_key key;
	    se3_flash_it it = { .addr = NULL };

	    key.id = SE3_KEYPAIR_ID_OFFSET  + 2 * req_params.sk_id;
	    key.data=malloc(kem_table[req_params.algo].display_secret_key_size);
	    if (key.id == SE3_KEY_INVALID) {
            SE3_TRACE(("[crypto_kem_dec] key id invalid\n"));
	        return SE3_ERR_PARAMS;
	    }
	    else {
	        se3_flash_it_init(&it);
	        if (!se3_key_find(key.id, &it)) {
	            it.addr = NULL;
	            SE3_TRACE(("[crypto_kem_dec] key not found\n"));
	            return SE3_ERR_RESOURCE;
	        }
	        se3_key_read(&it, &key);

			if (key.validity < se3_time_get() || !(get_now_initialized())) {
				SE3_TRACE(("[crypto_kem_dec] key expired\n"));
				return SE3_ERR_EXPIRED;
			}
	    }
	    se3_flash_key pms;
		pms.data_size=kem_table[req_params.algo].display_size;
	    pms.data=malloc(pms.data_size);

	    status = handler(pms.data, req_params.ct, key.data);

	    derive_and_store_keys(&pms,
	    		64,
				req_params.crsr,
				req_params.ms_id,
				req_params.cs_id,
				req_params.ss_id,
				req_params.validity,
				req_params.algo);

	    free(pms.data);
	    free(key.data);
	    return status;
}


/** \brief initialize a crypto context
 *
 *  crypto_init : (algo:ui16, mode:ui16, key_id:ui32) => (sid:ui32)
 */
uint16_t crypto_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t algo;
        uint16_t mode;
        uint32_t key_id;
    } req_params;
    struct {
        uint32_t sid;
    } resp_params;

    se3_flash_key key;
    se3_flash_it it = { .addr = NULL };
    se3_crypto_init_handler handler = NULL;
    uint32_t status;
    int sid;
    uint8_t* ctx;

    if (req_size != SE3_CMD1_CRYPTO_INIT_REQ_SIZE) {
        SE3_TRACE(("[crypto_init] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }

//    if (!se3_security_info.login.y) {
//        SE3_TRACE(("[crypto_init] not logged in\n"));
//        return SE3_ERR_ACCESS;
//    }

    SE3_GET16(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_ALGO, req_params.algo);
    SE3_GET16(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_MODE, req_params.mode);
    SE3_GET32(req, SE3_CMD1_CRYPTO_INIT_REQ_OFF_KEY_ID, req_params.key_id);

    if (req_params.algo < SE3_ALGO_MAX) {
        handler = algo_table[req_params.algo].init;
    }
    if (handler == NULL) {
        SE3_TRACE(("[crypto_init] algo not found\n"));
        return SE3_ERR_PARAMS;
    }

    // use request buffer to temporarily store key data
    // !! modifying request buffer
    key.data = (uint8_t*)req + 16;
    key.name = NULL;
    key.id = req_params.key_id;

    if (key.id == SE3_KEY_INVALID) {
        memset(key.data, 0, SE3_KEY_DATA_MAX);
    }
    else {
        se3_flash_it_init(&it);
        if (!se3_key_find(key.id, &it)) {
            it.addr = NULL;
        }
        if (NULL == it.addr) {
            SE3_TRACE(("[crypto_init] key not found\n"));
            return SE3_ERR_RESOURCE;
        }
        se3_key_read(&it, &key);

		if (key.validity < se3_time_get() || !(get_now_initialized())) {
			SE3_TRACE(("[crypto_init] key expired\n"));
			return SE3_ERR_EXPIRED;
		}
    }

    resp_params.sid = SE3_SESSION_INVALID;
    sid = se3_mem_alloc(&(se3_security_info.sessions), algo_table[req_params.algo].size);
    if (sid >= 0) {
        resp_params.sid = (uint32_t)sid;
    }

    if (resp_params.sid == SE3_SESSION_INVALID) {
        SE3_TRACE(("[crypto_init] cannot allocate session\n"));
        return SE3_ERR_MEMORY;
    }

    ctx = se3_mem_ptr(&(se3_security_info.sessions), sid);
    if (ctx == NULL) {
        // this should not happen
        SE3_TRACE(("[crypto_init] NULL session pointer\n"));
        return SE3_ERR_HW;
    }

    status = handler(&key, req_params.mode, ctx);

    if (SE3_OK != status) {
        // free the allocated session
        se3_mem_free(&(se3_security_info.sessions), (int32_t)resp_params.sid);

        SE3_TRACE(("[crypto_init] crypto handler failed\n"));
        return status;
    }

    // link session to algo
    se3_security_info.sessions_algo[resp_params.sid] = req_params.algo;

    SE3_SET32(resp, SE3_CMD1_CRYPTO_INIT_RESP_OFF_SID, resp_params.sid);

    *resp_size = SE3_CMD1_CRYPTO_INIT_RESP_SIZE;

	return SE3_OK;
}

/** \brief use a crypto context
 *
 *  crypto_update : (
 *      sid:ui32, flags:ui16, datain1-len:ui16, datain2-len:ui16, pad-to-16[6],
 *      datain1[datain1-len], pad-to-16[...], datain2[datain2-len])
 *  => (dataout-len, pad-to-16[14], dataout[dataout-len])
 */
uint16_t crypto_update(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint32_t sid;
        uint16_t flags;
        uint16_t datain0_len;
        uint16_t datain1_len;
        uint16_t datain2_len;
        const uint8_t* datain0;
        const uint8_t* datain1;
        const uint8_t* datain2;
    } req_params;
    struct {
        uint16_t dataout_len;
        uint8_t* dataout;
    } resp_params;
    uint16_t datain0_len_padded;
    uint16_t datain1_len_padded;
    se3_crypto_update_handler handler = NULL;
    uint16_t algo;
    uint8_t* ctx;
    uint16_t status;

    //se3_write_trace(se3_debug_create_string("\n[crypto_update] Start!\0"), debug_address++);

    if (req_size < SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA) {
        SE3_TRACE(("[crypto_update] req size mismatch\n"));
        //se3_write_trace(se3_debug_create_string("\n[crypto_update] req size mismatch\0"), debug_address++);
        return SE3_ERR_PARAMS;
    }

//    if (!se3_security_info.login.y) {
//        SE3_TRACE(("[crypto_update] not logged in\n"));
//        return SE3_ERR_ACCESS;
//    }

    SE3_GET32(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_SID, req_params.sid);
    SE3_GET16(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_FLAGS, req_params.flags);
    SE3_GET16(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN0_LEN, req_params.datain0_len);
    SE3_GET16(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN1_LEN, req_params.datain1_len);
    SE3_GET16(req, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN2_LEN, req_params.datain2_len);
    req_params.datain0 = req + SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA;
    if (req_params.datain0_len % 16) {
        datain0_len_padded = req_params.datain0_len + (16 - (req_params.datain0_len % 16));
    }
    else {
        datain0_len_padded = req_params.datain0_len;
    }
    req_params.datain1 = req + SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA + datain0_len_padded;

    if (req_params.datain1_len % 16) {
        datain1_len_padded = req_params.datain1_len + (16 - (req_params.datain1_len % 16));
    }
    else {
        datain1_len_padded = req_params.datain1_len;
    }
    req_params.datain2 = req + SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA + datain0_len_padded + datain1_len_padded;

    if (SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA + datain0_len_padded + datain1_len_padded + req_params.datain2_len > SE3_REQ1_MAX_DATA) {
        SE3_TRACE(("[crypto_update] data size exceeds packet limit\n"));
        //se3_write_trace(se3_debug_create_string("\n[crypto_update] data size exceeds packet limit\0"), debug_address++);
        return SE3_ERR_PARAMS;
    }

    if (req_params.sid >= SE3_SESSIONS_MAX) {
        SE3_TRACE(("[crypto_update] invalid sid\n"));
        return SE3_ERR_RESOURCE;
    }

    algo = se3_security_info.sessions_algo[req_params.sid];
    if (algo >= SE3_ALGO_MAX) {
        SE3_TRACE(("[crypto_update] invalid algo for this sid (wrong sid?)\n"));
        return SE3_ERR_RESOURCE;
    }

    handler = algo_table[algo].update;
    if (handler == NULL) {
        SE3_TRACE(("[crypto_update] invalid crypto handler for this algo (wrong sid?)\n"));
        return SE3_ERR_RESOURCE;
    }

    ctx = se3_mem_ptr(&(se3_security_info.sessions), (int32_t)req_params.sid);
    if (ctx == NULL) {
        SE3_TRACE(("[crypto_update] session not found\n"));
        return SE3_ERR_RESOURCE;
    }

    resp_params.dataout_len = 0;
    resp_params.dataout = resp + SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA;

    status = handler(
        ctx, req_params.flags,
        req_params.datain0_len, req_params.datain0,
        req_params.datain1_len, req_params.datain1,
        req_params.datain2_len, req_params.datain2,
        &(resp_params.dataout_len), resp_params.dataout);

    if (SE3_OK != status) {
        SE3_TRACE(("[crypto_update] crypto handler failed\n"));
        //se3_write_trace(se3_debug_create_string("\n[crypto_update] crypto handler failed\0"), debug_address++);
        return status;
    }

    if (req_params.flags & SE3_CRYPTO_FLAG_FINIT) {
        se3_mem_free(&(se3_security_info.sessions), (int32_t)req_params.sid);
    }

    SE3_SET16(resp, SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATAOUT_LEN, resp_params.dataout_len);
    *resp_size = SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA + resp_params.dataout_len;

    return SE3_OK;
}

/** \brief set device time for key validity
 *
 *  crypto_set_time : (devtime:ui32) => ()
 */
uint16_t crypto_set_time(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint32_t devtime;
    } req_params;

    if (req_size != SE3_CMD1_CRYPTO_SET_TIME_REQ_SIZE) {
        SE3_TRACE(("[crypto_set_time] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }
//    if (!se3_security_info.login.y) {
//        SE3_TRACE(("[crypto_set_time] not logged in\n"));
//        return SE3_ERR_ACCESS;
//    }

    SE3_GET32(req, SE3_CMD1_CRYPTO_SET_TIME_REQ_OFF_DEVTIME, req_params.devtime);

    se3_time_set((uint64_t)req_params.devtime);

    return SE3_OK;
}

/** \brief get list of available algorithms
 *
 *  crypto_list : () => (count:ui16, algoinfo0, algoinfo1, ...)
 *      algoinfo : (name[16], type:u16, block_size:u16, key_size:u16)
 */
uint16_t crypto_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp)
{
    struct {
        uint16_t count;
        uint8_t* algoinfo;
    } resp_params;
    uint8_t* p;
    size_t i;
    uint16_t size;

    if (req_size != SE3_CMD1_CRYPTO_LIST_REQ_SIZE) {
        SE3_TRACE(("[crypto_list] req size mismatch\n"));
        return SE3_ERR_PARAMS;
    }
//    if (!se3_security_info.login.y) {
//        SE3_TRACE(("[crypto_list] not logged in\n"));
//        return SE3_ERR_ACCESS;
//    }

    resp_params.algoinfo = resp + SE3_CMD1_CRYPTO_LIST_RESP_OFF_ALGOINFO;

    size = SE3_CMD1_CRYPTO_LIST_RESP_OFF_ALGOINFO;
    resp_params.count = 0;
    p = resp_params.algoinfo;
    for (i = 0; i < SE3_ALGO_MAX; i++) {
        if ((algo_table[i].init != NULL) && (algo_table[i].update != NULL)) {
            memcpy(p + SE3_CMD1_CRYPTO_ALGOINFO_OFF_NAME, algo_table[i].display_name, SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE);
            SE3_SET16(p, SE3_CMD1_CRYPTO_ALGOINFO_OFF_TYPE, algo_table[i].display_type);
            SE3_SET16(p, SE3_CMD1_CRYPTO_ALGOINFO_OFF_BLOCK_SIZE, algo_table[i].display_block_size);
            SE3_SET16(p, SE3_CMD1_CRYPTO_ALGOINFO_OFF_KEY_SIZE, algo_table[i].display_key_size);

            (resp_params.count)++;
            size += SE3_CMD1_CRYPTO_ALGOINFO_SIZE;
            p += SE3_CMD1_CRYPTO_ALGOINFO_SIZE;
        }
    }
    SE3_SET16(resp, SE3_CMD1_CRYPTO_LIST_RESP_OFF_COUNT, resp_params.count);
    *resp_size = size;
    return SE3_OK;
}

void se3_payload_cryptoinit(se3_payload_cryptoctx* ctx, const uint8_t* key)
{
	uint8_t keys[2 * B5_AES_256];

	PBKDF2HmacSha256(key, B5_AES_256, NULL, 0, 1, keys, 2 * B5_AES_256);
    B5_Aes256_Init(&(ctx->aesenc), keys, B5_AES_256, B5_AES256_CBC_ENC);
    B5_Aes256_Init(&(ctx->aesdec), keys, B5_AES_256, B5_AES256_CBC_DEC);
	memcpy(ctx->hmac_key, keys + B5_AES_256, B5_AES_256);
	memset(keys, 0, 2 * B5_AES_256);
}

bool se3_payload_encrypt(se3_payload_cryptoctx* ctx, uint8_t* auth, uint8_t* iv, uint8_t* data, uint16_t nblocks, uint16_t flags, uint8_t crypto_algo)
{
	switch(crypto_algo){
		case SE3_AES256:
		    if (flags & SE3_CMDFLAG_ENCRYPT) {
		        B5_Aes256_SetIV(&(ctx->aesenc), iv);
		        B5_Aes256_Update(&(ctx->aesenc),NULL, data, data, 0, nblocks);
		    } break;

		case SE3_CRC16:
			//to be implemented

		case SE3_PBKDF2:
			//to be implemented

		case SE3_SHA256:
			//to be implemented

		default: return false; break;
	}

    if (flags & SE3_CMDFLAG_SIGN) {
        B5_HmacSha256_Init(&(ctx->hmac), ctx->hmac_key, B5_AES_256);
        B5_HmacSha256_Update(&(ctx->hmac), iv, B5_AES_IV_SIZE);
        B5_HmacSha256_Update(&(ctx->hmac), data, nblocks*B5_AES_BLK_SIZE);
        B5_HmacSha256_Finit(&(ctx->hmac), ctx->auth);
        memcpy(auth, ctx->auth, 16);
    }
    else {
        memset(auth, 0, 16);
    }
    return true;
}

bool se3_payload_decrypt(se3_payload_cryptoctx* ctx, const uint8_t* auth, const uint8_t* iv, uint8_t* data, uint16_t nblocks, uint16_t flags, uint8_t crypto_algo)
{
    if (flags & SE3_CMDFLAG_SIGN) {
        B5_HmacSha256_Init(&(ctx->hmac), ctx->hmac_key, B5_AES_256);
        B5_HmacSha256_Update(&(ctx->hmac), iv, B5_AES_IV_SIZE);
        B5_HmacSha256_Update(&(ctx->hmac), data, nblocks*B5_AES_BLK_SIZE);
        B5_HmacSha256_Finit(&(ctx->hmac), ctx->auth);
        if (memcmp(auth, ctx->auth, 16)) {
            return false;
        }
    }

	switch(crypto_algo){
		case SE3_AES256:
		    if (flags & SE3_CMDFLAG_ENCRYPT) {
		        B5_Aes256_SetIV(&(ctx->aesdec), iv);
		        B5_Aes256_Update(&(ctx->aesdec), NULL, data, data,0, nblocks);
		    } break;

		case SE3_CRC16:
			//to be implemented

		case SE3_PBKDF2:
			//to be implemented

		case SE3_SHA256:
			//to be implemented

		default: return false; break;
	}


    return true;
}
