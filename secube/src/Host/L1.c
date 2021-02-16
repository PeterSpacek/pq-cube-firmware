#include "L1.h"
#include "sha256.h"
#include "aes256.h"

static uint16_t key_list(se3_session* s, uint16_t skip, uint16_t max_keys, const uint8_t* salt, se3_key* key_array, uint16_t* count);
static void se3_session_init(se3_session* s, se3_device* dev);
static uint16_t L1_TXRX(se3_session* s, uint16_t cmd, uint16_t cmd_flags, uint16_t req_len, uint16_t* resp_len);

static uint16_t L1_TXRX(se3_session* s, uint16_t cmd, uint16_t cmd_flags, uint16_t req_len, uint16_t* resp_len)
{
	uint16_t result;
	uint16_t u16tmp = 0;
	uint16_t req_len_padded, req0_len;
	uint16_t resp0_len = 0, resp_status = 0;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;

	uint8_t* req_iv = s->buf + SE3_REQ1_OFFSET_IV,
		*req_auth = s->buf + SE3_REQ1_OFFSET_AUTH;
	uint8_t* resp_iv = s->buf + SE3_RESP1_OFFSET_IV,
		*resp_auth = s->buf + SE3_RESP1_OFFSET_AUTH;

	// set headers
	if (s->logged_in) {
		memcpy(s->buf + SE3_REQ1_OFFSET_TOKEN, s->token, SE3_L1_TOKEN_SIZE);
	}
	else {
		memset(s->buf + SE3_REQ1_OFFSET_TOKEN, 0, SE3_L1_TOKEN_SIZE);
	}
	SE3_SET16(s->buf, SE3_REQ1_OFFSET_CMD, cmd);
	SE3_SET16(s->buf, SE3_REQ1_OFFSET_LEN, req_len);

	req_len_padded = req_len;
	if (req_len_padded % SE3_L1_CRYPTOBLOCK_SIZE != 0) {
		memset(session_data + req_len_padded, 0, (SE3_L1_CRYPTOBLOCK_SIZE - (req_len_padded % SE3_L1_CRYPTOBLOCK_SIZE)));
		req_len_padded += (SE3_L1_CRYPTOBLOCK_SIZE - (req_len_padded % SE3_L1_CRYPTOBLOCK_SIZE));
	}

	req0_len = SE3_REQ1_OFFSET_DATA + req_len_padded;

	// encrypt
	if (!(s->cryptoctx_initialized)) {
		se3_payload_cryptoinit(&(s->cryptoctx), s->key);
		s->cryptoctx_initialized = true;
	}
	if (cmd_flags & SE3_CMDFLAG_ENCRYPT) {
		se3c_rand(SE3_L1_CRYPTOBLOCK_SIZE, req_iv);
	}
	else {
		memset(req_iv, 0, SE3_L1_CRYPTOBLOCK_SIZE);
	}
	se3_payload_encrypt(
		&(s->cryptoctx), req_auth, req_iv,
		(s->buf + SE3_L1_AUTH_SIZE + SE3_L1_IV_SIZE), (req0_len - SE3_L1_AUTH_SIZE - SE3_L1_IV_SIZE) / SE3_L1_CRYPTOBLOCK_SIZE, cmd_flags);

	resp0_len = SE3_COMM_N*SE3_COMM_BLOCK;
	result = L0_TXRX(&(s->device), SE3_CMD0_L1, cmd_flags, req0_len, s->buf, &resp_status, &resp0_len, s->buf);

	// comm error status
	if (result != SE3_OK) {
		return result;
	}

	// L0 error status from device
	if (resp_status != SE3_OK) {
		return resp_status;
	}

	if (resp0_len < SE3_RESP1_OFFSET_DATA) {
		return SE3_ERR_COMM;
	}

	//decrypt
	if (!se3_payload_decrypt(
		&(s->cryptoctx), resp_auth, resp_iv,
		s->buf + SE3_L1_AUTH_SIZE + SE3_L1_IV_SIZE,
		(resp0_len - SE3_L1_AUTH_SIZE - SE3_L1_IV_SIZE) / SE3_L1_CRYPTOBLOCK_SIZE, cmd_flags))
	{
		SE3_TRACE(("[L0d_cmd1] AUTH failed\n"));
		return SE3_ERR_COMM;
	}
	
	SE3_GET16(s->buf, SE3_RESP1_OFFSET_LEN, u16tmp);
	*resp_len = u16tmp;
	SE3_GET16(s->buf, SE3_RESP1_OFFSET_STATUS, u16tmp);
	// L1 status
	return u16tmp;
}

static void se3_session_init(se3_session* s, se3_device* dev) {
	memset(s, 0, sizeof(se3_session));
	s->logged_in = false;
	memcpy(&(s->device), dev, sizeof(se3_device));
	memcpy(s->key, se3_magic, SE3_L1_KEY_SIZE);
	s->cryptoctx_initialized = false;
}

uint16_t L1_login(se3_session* s, se3_device* dev, const uint8_t* pin, uint16_t access) {
	uint8_t cc1[SE3_L1_CHALLENGE_SIZE], cc2[SE3_L1_CHALLENGE_SIZE], sc[SE3_L1_CHALLENGE_SIZE], sresp_expected[SE3_L1_CHALLENGE_SIZE];
	uint16_t req_len = 0, resp_len = 0;
	uint16_t error;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;
	// only for login
	se3_session_init(s, dev);

	// Prepare data to be sent
	//memset(s->buf, 0, SE3_COMM_N * SE3_COMM_BLOCK);   // Clear buffer
	se3c_rand(SE3_L1_CHALLENGE_SIZE, cc1);   // Generates 2 randoms for Challenge
	se3c_rand(SE3_L1_CHALLENGE_SIZE, cc2);

	memcpy(session_data + SE3_CMD1_CHALLENGE_REQ_OFF_CC1, cc1, SE3_L1_CHALLENGE_SIZE);
	memcpy(session_data + SE3_CMD1_CHALLENGE_REQ_OFF_CC2, cc2, SE3_L1_CHALLENGE_SIZE);
	SE3_SET16(session_data, SE3_CMD1_CHALLENGE_REQ_OFF_ACCESS, access);

	req_len = SE3_CMD1_CHALLENGE_REQ_OFF_ACCESS + sizeof(uint16_t);

	// Send Challenge
	error = L1_TXRX(s, SE3_CMD1_CHALLENGE, 0, req_len, &resp_len);
	if (error != SE3_OK) {
		return error;
	}
	// TODO check response length

	// Read Server Challenge sc
	memcpy(sc, session_data + SE3_CMD1_CHALLENGE_RESP_OFF_SC, SE3_L1_CHALLENGE_SIZE);

	// check server response
	// sresp = PBKDF2(HMACSHA256, pin, cc1, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
	PBKDF2HmacSha256(pin, SE3_L1_PIN_SIZE, cc1,
		SE3_L1_CHALLENGE_SIZE, SE3_L1_CHALLENGE_ITERATIONS, sresp_expected, SE3_L1_CHALLENGE_SIZE);

	if (memcmp(sresp_expected, session_data + SE3_CMD1_CHALLENGE_RESP_OFF_SRESP, SE3_L1_CHALLENGE_SIZE)) {
		return SE3_ERR_PIN;
	}
	//memset(s->buf, 0, SE3_COMM_N * SE3_COMM_BLOCK);   // Clear buffer

	// Prepare session key

	// key = PBKDF2(HMACSHA256, pin, cc2, 1, SE3_L1_PIN_SIZE)
	PBKDF2HmacSha256(pin, SE3_L1_PIN_SIZE, cc2,
		SE3_L1_CHALLENGE_SIZE, 1, s->key, SE3_L1_PIN_SIZE);

	s->logged_in = true;

	// --- Encryption can begin here ---

	// Prepare Challenge Response

	// cresp = PBKDF2(HMACSHA256, pin, sc, SE3_L1_CHALLENGE_ITERATIONS, SE3_CHALLENGE_SIZE)
	PBKDF2HmacSha256(pin, SE3_L1_PIN_SIZE, sc,
		SE3_L1_CHALLENGE_SIZE, SE3_L1_CHALLENGE_ITERATIONS,
		session_data + SE3_CMD1_LOGIN_REQ_OFF_CRESP, SE3_L1_CHALLENGE_SIZE);

	req_len = SE3_L1_CHALLENGE_SIZE;

	// Send Login command
	error = L1_TXRX(s, SE3_CMD1_LOGIN, SE3_CMDFLAG_ENCRYPT | SE3_CMDFLAG_SIGN, req_len, &resp_len);
	if (error != SE3_OK) {
		s->logged_in = false;
		return error;
	}
	// TODO check response length

	// Read Token
	memcpy(s->token, session_data + SE3_CMD1_LOGIN_RESP_OFF_TOKEN, SE3_L1_TOKEN_SIZE);

	// s->logged_in = true;  // moved up

	return(SE3_OK);
}



uint16_t L1_logout(se3_session* s) {
	uint16_t data_len = 0;
	uint16_t resp_len = 0;
	uint16_t error = 0;
	if (!s->logged_in) {
		return SE3_ERR_STATE;
	}
	error = L1_TXRX(s, SE3_CMD1_LOGOUT, 0, data_len, &resp_len);
	if (error != SE3_OK) {
		return error;
	}
	s->logged_in = false;
	return(SE3_OK);
}


uint32_t L1_config(se3_session* s, uint16_t type, uint16_t op, uint8_t* value) {
	// config : (type:ui16, op:ui16, value[32]) => (value[32])
	// resp::value is empty (zeros) if op=SET
	// req::value is empty (zeros) if op=GET

	uint16_t datalen = 0, resp_len = 0;
	uint16_t error = 0;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;

	SE3_SET16(session_data, SE3_CMD1_CONFIG_REQ_OFF_ID, type);   //set type
	SE3_SET16(session_data, SE3_CMD1_CONFIG_REQ_OFF_OP, op);   //set op
	if (op == SE3_CONFIG_OP_GET) {   //set value
		memset(session_data + SE3_CMD1_CONFIG_REQ_OFF_VALUE, 0, SE3_RECORD_SIZE);   //write value (all 0s)
	}
	if (op == SE3_CONFIG_OP_SET) {
		memcpy(session_data + SE3_CMD1_CONFIG_REQ_OFF_VALUE, value, SE3_RECORD_SIZE);   //write value
	}

	datalen = 2 + 2 + SE3_RECORD_SIZE;   // type + op + value
	error = L1_TXRX(s, SE3_CMD1_CONFIG, SE3_CMDFLAG_ENCRYPT | SE3_CMDFLAG_SIGN, datalen, &resp_len);
	if (error != SE3_OK) {
		return error;
	}

	// Now in session_data there is the response
	if (op == SE3_CONFIG_OP_GET) {
		memcpy(value, session_data + SE3_CMD1_CONFIG_RESP_OFF_VALUE, SE3_RECORD_SIZE);
	}

	// return(value);
	return SE3_OK;
}


uint16_t L1_set_admin_PIN(se3_session* s, uint8_t* pin) {
	/* TODO: Add flag at se3_session for type of user
	and provide here checks to avoid to set PIN if not logged
	just let the board fail  ^
	*/
	return L1_config(s, SE3_RECORD_TYPE_ADMINPIN, SE3_CONFIG_OP_SET, pin);
}


uint16_t L1_set_user_PIN(se3_session* s, uint8_t* pin) {
	/* TODO: Add flag at se3_session for type of user
	and provide here checks to avoid to set PIN if not logged
	just let the board fail  ^
	*/
	return L1_config(s, SE3_RECORD_TYPE_USERPIN, SE3_CONFIG_OP_SET, pin);
}


uint16_t L1_key_edit(se3_session* s, uint16_t op, se3_key* k) {
	uint16_t data_len = 0;
	uint16_t resp_len = 0;
	uint16_t error = 0;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;
	if (k == NULL) {
		return(SE3_ERR_PARAMS);
	}

	SE3_SET16(session_data, SE3_CMD1_KEY_EDIT_REQ_OFF_OP, op);
	SE3_SET32(session_data, SE3_CMD1_KEY_EDIT_REQ_OFF_ID, k->id);
	SE3_SET32(session_data, SE3_CMD1_KEY_EDIT_REQ_OFF_VALIDITY, k->validity);
	SE3_SET16(session_data, SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_LEN, k->data_size);
	SE3_SET16(session_data, SE3_CMD1_KEY_EDIT_REQ_OFF_NAME_LEN, k->name_size);
	memcpy(session_data + SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_AND_NAME, k->data, k->data_size);
	memcpy(session_data + SE3_CMD1_KEY_EDIT_REQ_OFF_DATA_AND_NAME + k->data_size, k->name, k->name_size);

	data_len = 2 + 4 + 4 + 2 + 2 + k->data_size + k->name_size;   // op + id + validity + data_size + name_size + data + name
	error = L1_TXRX(s, SE3_CMD1_KEY_EDIT, SE3_CMDFLAG_ENCRYPT | SE3_CMDFLAG_SIGN, data_len, &resp_len);
	if (error != SE3_OK) {
		return error;
	}

	return(SE3_OK);
}

static uint16_t key_list(se3_session* s, uint16_t skip, uint16_t max_keys, const uint8_t* salt, se3_key* key_array, uint16_t* count) {
	uint16_t error = 0;
	uint16_t resp_len = 0;
	uint16_t n_keys = 0;
	uint16_t i = 0;
	uint16_t offset_key = 0;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;
	uint8_t salt_[SE3_KEY_SALT_SIZE];
	// Check parameters
	if (max_keys <= 0 || skip < 0) {
		return(SE3_ERR_PARAMS);
	}
	if (salt == NULL) {
		memset(salt_, 0, SE3_KEY_SALT_SIZE);
	}
	else {
		memcpy(salt_, salt, SE3_KEY_SALT_SIZE);
	}

	// Set data
	SE3_SET16(session_data, SE3_CMD1_KEY_LIST_REQ_OFF_SKIP, skip);
	SE3_SET16(session_data, SE3_CMD1_KEY_LIST_REQ_OFF_NMAX, max_keys);
	memcpy(session_data + SE3_CMD1_KEY_LIST_REQ_OFF_SALT, salt_, SE3_KEY_SALT_SIZE);

	// Send data
	error = L1_TXRX(s, SE3_CMD1_KEY_LIST, 0, SE3_CMD1_KEY_LIST_REQ_SIZE, &resp_len);
	if (error != SE3_OK) {
		return error;
	}

	// Read response
	SE3_GET16(session_data, SE3_CMD1_KEY_LIST_RESP_OFF_COUNT, n_keys);   // Get number of keys returned
	//if(n_keys == 0) return(???)
	offset_key = 2;
	for (i = 0; i < n_keys; i++) {   // Fills with key received
		SE3_GET32(session_data, offset_key + SE3_CMD1_KEY_LIST_KEYINFO_OFF_ID, key_array[i].id);
		SE3_GET32(session_data, offset_key + SE3_CMD1_KEY_LIST_KEYINFO_OFF_VALIDITY, key_array[i].validity);
		SE3_GET16(session_data, offset_key + SE3_CMD1_KEY_LIST_KEYINFO_OFF_DATA_LEN, key_array[i].data_size);
		SE3_GET16(session_data, offset_key + SE3_CMD1_KEY_LIST_KEYINFO_OFF_NAME_LEN, key_array[i].name_size);
		memcpy(key_array[i].fingerprint, session_data + offset_key + SE3_CMD1_KEY_LIST_KEYINFO_OFF_FINGERPRINT, SE3_KEY_FINGERPRINT_SIZE);
		memcpy(key_array[i].name, session_data + offset_key + SE3_CMD1_KEY_LIST_KEYINFO_OFF_NAME, key_array[i].name_size);
		offset_key += SE3_CMD1_KEY_LIST_KEYINFO_OFF_NAME + key_array[i].name_size;
	}

	*count = n_keys;

	return(SE3_OK);
}

uint16_t L1_key_list(se3_session* s, uint16_t skip, uint16_t max_keys, const uint8_t* salt, se3_key* key_array, uint16_t* count) {
	int i = 0;
	uint16_t return_value = 0, xcount = 0;
	while (i != max_keys &&
		(return_value = key_list(s, i + skip, max_keys - i, salt, &(key_array[i]), &xcount)) == 0 &&
		xcount>0){
		i += xcount;
	}
	*count = i;
	return return_value;
}

bool L1_find_key(se3_session* s, uint32_t key_id){
	enum{
		FIND_KEY_NUM = 50
	};
	se3_key key_array[FIND_KEY_NUM];
	uint16_t ret = SE3_OK, count = 0;
	int i = 0, j = 0;
	while ((ret = L1_key_list(s, i, i + FIND_KEY_NUM, NULL, key_array, &count)) == SE3_OK && count>0){
		for (j = 0; j<count; j++){
			if (key_array[j].id == key_id) return true;
		}
		i += count;
	}
	return false;
}


//L1_crypto_init: (algo:ui16, mode : ui16, key_id : ui32) = > (sid:ui32)
uint16_t L1_crypto_init(se3_session* s, uint16_t algorithm, uint16_t mode, uint32_t key_id, uint32_t* sess_id) {
	uint16_t error = 0;
	uint16_t resp_len = 0;
	uint32_t u32tmp = 0;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;
	// Prepare data
	SE3_SET16(session_data, SE3_CMD1_CRYPTO_INIT_REQ_OFF_ALGO, algorithm);
	SE3_SET16(session_data, SE3_CMD1_CRYPTO_INIT_REQ_OFF_MODE, mode);
	SE3_SET32(session_data, SE3_CMD1_CRYPTO_INIT_REQ_OFF_KEY_ID, key_id);

	// Send data
	error = L1_TXRX(s, SE3_CMD1_CRYPTO_INIT, 0, SE3_CMD1_CRYPTO_INIT_REQ_SIZE, &resp_len);
	if (error != SE3_OK) {
		return error;
	}

	// Read response
	SE3_GET32(session_data, SE3_CMD1_CRYPTO_INIT_RESP_OFF_SID, u32tmp);   // extract Session ID
	*sess_id = u32tmp;

	return(SE3_OK);
}


// L1_crypto_update : (sid:ui32, flags : ui16, datain1 - len : ui16, datain2 - len : ui16, 
//					pad - to - 16[6], *datain1[datain1 - len], pad - to - 16[...], datain2[datain2 - len])
// = > (dataout - len, pad - to - 16[14], dataout[dataout - len]
uint16_t L1_crypto_update(se3_session* s,
	uint32_t sess_id,
	uint16_t flags,
	uint16_t data1_len,
	const uint8_t* data1,
	uint16_t data2_len,
	const uint8_t* data2,
	uint16_t* dataout_len,
	uint8_t* data_out) {
	uint16_t error = 0;
	uint16_t resp_len = 0;
	uint16_t data_len = 0;
	uint16_t data1_len_pad16 = 0;
	uint16_t u16tmp;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;
	// Prepare data
	//memset(session_data, 0, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA);   // Clear buffer
	SE3_SET32(session_data, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_SID, sess_id);   // Session ID
	SE3_SET16(session_data, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_FLAGS, flags);   // Flags
	SE3_SET32(session_data, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN1_LEN, data1_len);   // Length of Data1
	SE3_SET32(session_data, SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATAIN2_LEN, data2_len);   // Length of Data2
	// compute offset for data2
	if (data1_len % 16 != 0) {
		data1_len_pad16 = data1_len + (16 - (data1_len % 16));
	}
	else {
		data1_len_pad16 = data1_len;
	}
	// check whether we exceed buffer length
	data_len = SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA + data1_len_pad16 + data2_len;
	if (data_len > SE3_REQ1_MAX_DATA) {
		return SE3_ERR_PARAMS;
	}
	// copy data1
	if (data1_len > 0) {
		memcpy(session_data + SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA, data1, data1_len);
	}
	//copy data2
	if (data2_len > 0) {
		memcpy(session_data + SE3_CMD1_CRYPTO_UPDATE_REQ_OFF_DATA + data1_len_pad16, data2, data2_len);
	}

	// Send data

	error = L1_TXRX(s, SE3_CMD1_CRYPTO_UPDATE, 0, data_len, &resp_len);
	if (error != SE3_OK) {
		return error;
	}

	// Read response
	SE3_GET16(session_data, SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATAOUT_LEN, u16tmp);   // extract length of output data
	if (dataout_len != NULL)
		*dataout_len = u16tmp;
	if (data_out != NULL)
		memcpy(data_out, session_data + SE3_CMD1_CRYPTO_UPDATE_RESP_OFF_DATA, u16tmp);   // extract output data


	return(SE3_OK);
}


uint16_t L1_get_algorithms(se3_session* s,
	uint16_t skip,
	uint16_t max_algorithms,
	se3_algo* algorithms_array,
	uint16_t* count) {
	uint16_t error = 0;
	uint16_t resp_len = 0;
	uint16_t n_algo = 0;
	size_t offset_algo = 0;
	uint16_t i = 0;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;

	// Check parameters
	if (max_algorithms <= 0 || skip < 0) {
		return(SE3_ERR_PARAMS);
	}

	// Send request
	error = L1_TXRX(s, SE3_CMD1_CRYPTO_LIST, 0, SE3_CMD1_CRYPTO_LIST_REQ_SIZE, &resp_len);
	if (error != SE3_OK) {
		return error;
	}

	// Read response
	SE3_GET16(session_data, SE3_CMD1_CRYPTO_LIST_RESP_OFF_COUNT, n_algo);   // extract number of algorithms returned
	offset_algo = SE3_CMD1_CRYPTO_LIST_RESP_OFF_ALGOINFO + skip * SE3_CMD1_CRYPTO_ALGOINFO_SIZE;
	size_t j = 0;
	for (i = 0, j = skip; i < max_algorithms && j < n_algo; i++, j++) {   // Fills array with algorithm(s) received
		memcpy(algorithms_array[i].name, session_data + offset_algo + SE3_CMD1_CRYPTO_ALGOINFO_OFF_NAME, SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE);
		SE3_GET16(session_data + offset_algo, SE3_CMD1_CRYPTO_ALGOINFO_OFF_TYPE, algorithms_array[i].type);
		SE3_GET16(session_data + offset_algo, SE3_CMD1_CRYPTO_ALGOINFO_OFF_BLOCK_SIZE, algorithms_array[i].block_size);
		SE3_GET16(session_data + offset_algo, SE3_CMD1_CRYPTO_ALGOINFO_OFF_KEY_SIZE, algorithms_array[i].key_size);
		offset_algo += SE3_CMD1_CRYPTO_ALGOINFO_SIZE;
	}
	*count = i;

	return(SE3_OK);
}


uint16_t L1_crypto_set_time(se3_session* s, uint32_t devtime){
	uint16_t return_value = 0, resp_len = 0;
	uint32_t current_time = devtime;
	uint8_t* session_data = s->buf + SE3_RESP1_OFFSET_DATA;

	SE3_SET32(session_data, SE3_CMD1_CRYPTO_SET_TIME_REQ_OFF_DEVTIME, current_time);

	return_value = L1_TXRX(s, SE3_CMD1_CRYPTO_SET_TIME, 0, SE3_CMD1_CRYPTO_SET_TIME_REQ_SIZE, &resp_len);

	return return_value;
}


uint16_t L1_encrypt(se3_session* s, uint16_t algorithm, uint16_t mode, uint32_t key_id, size_t datain_len, uint8_t* data_in, size_t* dataout_len, uint8_t* data_out) {
	uint8_t* sp = data_in, *rp = data_out;
	uint16_t error = SE3_OK;
	uint16_t curr_len = 0;
	uint32_t enc_sess_id = 0;
	size_t curr_chunk = datain_len < SE3_CRYPTO_MAX_DATAIN ? datain_len : SE3_CRYPTO_MAX_DATAIN;

	if (datain_len < 0 || data_out == NULL)
		return(SE3_ERR_PARAMS);


	error = L1_crypto_init(s, algorithm, mode, key_id, &enc_sess_id);
	if (error != SE3_OK) {
		return error;
	}

	if (dataout_len != NULL)
		*dataout_len = 0;

	if ((algorithm & SE3_ALGO_AES_HMAC) && curr_chunk == SE3_CRYPTO_MAX_DATAIN){
		curr_chunk -= B5_SHA256_DIGEST_SIZE;
	}
	do {
		if (datain_len - curr_chunk)
			error = L1_crypto_update(s, enc_sess_id, mode, 0, NULL, (uint16_t)curr_chunk, sp, &curr_len, rp);
		else
			error = L1_crypto_update(s, enc_sess_id, SE3_CRYPTO_FLAG_FINIT | mode, 0, NULL, (uint16_t)curr_chunk, sp, &curr_len, rp);

		datain_len -= curr_chunk;
		sp += curr_chunk;
		rp += curr_chunk;
		curr_chunk = datain_len < SE3_CRYPTO_MAX_DATAIN ? datain_len : SE3_CRYPTO_MAX_DATAIN;
		if ((algorithm & SE3_ALGO_AES_HMAC) && curr_chunk == SE3_CRYPTO_MAX_DATAIN){
			curr_chunk -= B5_SHA256_DIGEST_SIZE;
		}

		if (dataout_len != NULL)
			*dataout_len += curr_len;

	} while (datain_len > 0);


	return(error);
}

uint16_t L1_decrypt(se3_session* s, uint16_t algorithm, uint16_t mode, uint32_t key_id, size_t datain_len, uint8_t* data_in, size_t* dataout_len, uint8_t* data_out) {
	return L1_encrypt(s, algorithm, mode, key_id, datain_len, data_in, dataout_len, data_out);
}

uint16_t L1_digest(se3_session* s, uint16_t algorithm, size_t datain_len, uint8_t* data_in, size_t* dataout_len, uint8_t* data_out) {
	uint8_t* sp = data_in, *rp = data_out;
	uint16_t error = SE3_OK;
	uint16_t curr_len = 0;
	size_t curr_chunk = datain_len < SE3_CRYPTO_MAX_DATAIN ? datain_len : SE3_CRYPTO_MAX_DATAIN;
	uint32_t enc_sess_id = 0;

	if (datain_len < 0 || data_out == NULL)
		return(SE3_ERR_PARAMS);


	error = L1_crypto_init(s, algorithm, 0, 0, &enc_sess_id);
	if (error != SE3_OK) {
		return error;
	}

	if (dataout_len != NULL)
		*dataout_len = 0;

	do {
		if (datain_len - curr_chunk)
			error = L1_crypto_update(s, enc_sess_id, 0, (uint16_t)curr_chunk, sp, 0, NULL, &curr_len, rp);
		else
			error = L1_crypto_update(s, enc_sess_id, SE3_CRYPTO_FLAG_FINIT, (uint16_t)curr_chunk, sp, 0, NULL, &curr_len, rp);

		datain_len -= curr_chunk;
		sp += curr_chunk;
		curr_chunk = datain_len < SE3_CRYPTO_MAX_DATAIN ? datain_len : SE3_CRYPTO_MAX_DATAIN;
		
		if(dataout_len != NULL)	
			*dataout_len += curr_len;
	

	} while (datain_len > 0);


	return(error);
}

