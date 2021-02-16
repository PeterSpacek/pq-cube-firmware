/**
 *  \file L1.h
 *  \brief This file contains L1 functions and structures
 * 
 */

#pragma once
#include "L0.h"
#include "se3c1def.h"


/* defines */
#define SE3_REQ_CHALLENGE_SIZE   (96+16)
#define SE3_REQ_CHALLENGE_IV_OFFSET   (0)
#define SE3_REQ_CHALLENGE_TOKEN_OFFSET   (16)
#define SE3_REQ_CHALLENGE_CC_OFFSET   (32)
#define SE3_REQ_CHALLENGE_CC2_OFFSET   (64)
#define SE3_REQ_CHALLENGE_ACCESS_OFFSET   (96)

#define SE3_RESP_CHALLENGE_SC_OFFSET   (32)
#define SE3_RESP_LOGIN_TOKEN_OFFSET   (32)

/* END - defines */



#ifdef __cplusplus
extern "C" {
#endif

/* struct */
/** \brief SEcube Communication session structure */
typedef struct se3_session_ {
	se3_device device;
	uint8_t token[SE3_L1_TOKEN_SIZE];
	uint8_t key[SE3_L1_KEY_SIZE];
	uint8_t buf[SE3_COMM_N * SE3_COMM_BLOCK];
	bool locked;
	bool logged_in;
	uint32_t timeout;
	se3_file hfile;
	se3_payload_cryptoctx cryptoctx;
	bool cryptoctx_initialized;
	// TODO: Add flag for type of user logged (see set_{admin,user}_PIN) or change type for logged_in
} se3_session;

/** \brief SEcube Key structure */
typedef struct se3_key_ {
	uint32_t id;
	uint32_t validity;
	uint16_t data_size;
	uint16_t name_size;
	uint8_t fingerprint[SE3_KEY_FINGERPRINT_SIZE];
	uint8_t* data;
	uint8_t name[SE3_KEY_NAME_MAX];
} se3_key;

/** \brief SEcube Algorithm structure */
typedef struct se3_algo_ {
	uint8_t name[SE3_CMD1_CRYPTO_ALGOINFO_NAME_SIZE];
	uint16_t type;
	uint16_t block_size;
	uint16_t key_size;
} se3_algo;


/* END - struct */

/**
*  \brief This function is used to let a user/admin login on the
*  	   device
*
*  \param [out] s Pointer to an already allocated se3_session object
*  			   where to store current logged in session
*  \param [in] dev Device you want to login to
*  \param [in] pin Password to login
*  \param [in] access see \ref AccessLogin
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*  \details Before issueing any command to the device, you need to login.
*  		 Some operations are allowed only to the admin user.
*  		 After a flash erase, the admin pin and the user pin are both
*  		 a sequence of 32 0s, please use \ref L1_set_admin_PIN or
*  		 \ref L1_set_user_PIN to change them.
*/
uint16_t L1_login(se3_session* s, se3_device* dev, const uint8_t* pin, uint16_t access);
/**
*  \brief This function is used to change the current admin pin
*
*  \param [in] s Pointer to current se3_session, you must be logged in as admin to issue
*  			  this command
*  \param [in] pin New pin to be set
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*/
uint16_t L1_set_admin_PIN(se3_session* s, uint8_t* pin);


uint32_t L1_config(se3_session* s, uint16_t type, uint16_t op, uint8_t* value);

/**
*  \brief This function is used to change the current user pin
*
*  \param [in] s Pointer to current se3_session, you must be logged in as admin to issue
*  			  this command
*  \param [in] pin New pin to be set
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*/
uint16_t L1_set_user_PIN(se3_session* s, uint8_t* pin);

/**
*  \brief This function is used to logout from the device
*
*  \param [in] s Current session you want to end
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*  \details After issueing this function, you will be forbidden to perform
*  		 any command on the device. This can also be used to free the
*  		 allocated resources, such as cryptographic sessions, with just one
*  		 call.
*/
uint16_t L1_logout(se3_session* s);
/**
*  \brief This function is used get the list of the already of the already
*  	   available keys on the device.
*
*  \param [in] s Pointer to current se3_session, you must be logged in
*  \param [in] skip How many keys you want to skip from the beginning of the list
*  \param [in] max_keys How many keys you want to retrieve from the device
*  \param [out] key_array Pointer to the already allocated array where to store the keys
*  \param [out] count Effective number of retrieved keys
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*/
uint16_t L1_key_list(se3_session* s, uint16_t skip, uint16_t max_keys, const uint8_t* salt, se3_key* key_array, uint16_t* count);
/**
*  \brief This function is used to edit the keys data on the device
*
*  \param [in] s Pointer to current se3_session, you must be logged in
*  \param [in] op see \ref KeyOpEdit
*  \param [in] k Key value you want to add/update/delete
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*/
uint16_t L1_key_edit(se3_session* s, uint16_t op, se3_key* k);

/**
 *  \brief Check if a Key is present or not
 *  
 *  \param [in] s Pointer to current se3_session, you must be logged in
 *  \param [in] key_id ID of key to be found
 *  \return true if key is found, false otherwise
 *  
 */
bool L1_find_key(se3_session* s, uint32_t key_id);

/**
 *  \brief Initialise a crypto session
 *  
 *  \param [in] s Pointer to current se3_session, you must be logged in
 *  \param [in] algorithm Which algorithm to use, see \ref AlgorithmAvail
 *  \param [in] mode This parameter strictly depends on the which algorithm is chosen
 *  \param [in] key_id Which key ID to use for encryption
 *  \param [in] sess_id Session ID
 *  \return Error code or SE3_OK
 *  
 */
uint16_t L1_crypto_init(se3_session* s, uint16_t algorithm, uint16_t mode, uint32_t key_id, uint32_t* sess_id);

/**
 *  \brief Update a crypto session
 *  
 *  \param [in] s Pointer to current se3_session, you must be logged in
 *  \param [in] sess_id Session ID
 *  \param [in] flags Parameter_Description
 *  \param [in] data1_len How long is the buffer you want to encrypt
 *  \param [in] data1 Pointer to input buffer 1
 *  \param [in] data2_len Length of input buffer 1
 *  \param [in] data2 Pointer to input buffer 2
 *  \param [out] dataout_len Length of input buffer 1
 *  \param [out] data_out Pointer to the output buffer
 *  \return Error code or SE3_OK
 *  
 */
uint16_t L1_crypto_update(se3_session* s, uint32_t sess_id, uint16_t flags, uint16_t data1_len, const uint8_t* data1, uint16_t data2_len, const uint8_t* data2, uint16_t* dataout_len, uint8_t* data_out);

/**
 *  \brief Set time for a crypto session
 *  
 *  \param [in] s Pointer to current se3_session, you must be logged in
 *  \param [in] devtime Time to be set
 *  \return Error code or SE3_OK
 *   
 */
uint16_t L1_crypto_set_time(se3_session* s, uint32_t devtime);

/**
*  \brief This function is used to encrypt a buffer of data given the algorithm,
*  	   the encryption mode, the buffer size, and where to store the encrypted
*  	   data
*
*  \param [in] s Pointer to current se3_session, you must be logged in
*  \param [in] algorithm Which algorithm to use, see \ref AlgorithmAvail
*  \param [in] mode This parameter strictly depends on the which algorithm is chosen
*  \param [in] key_id Which key ID to use for encryption
*  \param [in] datain_len How long is the buffer you want to encrypt
*  \param [in] data_in Pointer to the buffer
*  \param [out] dataout_len How many data were actually encrypted
*  \param [out] data_out Pointer to a pre-allocated buffer where to store the cipher text
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*/
uint16_t L1_encrypt(se3_session* s, uint16_t algorithm, uint16_t mode, uint32_t key_id, size_t datain_len, uint8_t* data_in, size_t* dataout_len, uint8_t* data_out);
/**
*  \brief This function is used to decrypt a buffer of data given the algorithm,
*  	   the decryption mode, the buffer size, and where to store the decrypted
*  	   data
*
*  \param [in] s Pointer to current se3_session, you must be logged in
*  \param [in] algorithm Which algorithm to use, see \ref AlgorithmAvail
*  \param [in] mode This parameter strictly depends on the which algorithm is chosen
*  \param [in] key_id Which key ID to use for decryption
*  \param [in] datain_len How long is the buffer you want to decrypt
*  \param [in] data_in Pointer to the buffer
*  \param [out] dataout_len How many data were actually decrypted
*  \param [out] data_out Pointer to a pre-allocated buffer where to store the clear text
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*/
uint16_t L1_decrypt(se3_session* s, uint16_t algorithm, uint16_t mode, uint32_t key_id, size_t datain_len, uint8_t* data_in, size_t* dataout_len, uint8_t* data_out);
/**
*  \brief This function is used to sign a buffer of data given the algorithm,
*  	   the amount of data to sign and where to store them
*
*  \param [in] s Pointer to current se3_session, you must be logged in
*  \param [in] algorithm Which algorithm to use, see \ref AlgorithmAvail
*  \param [in] datain_len How long is the buffer you want to sign
*  \param [in] data_in Pointer to the buffer
*  \param [out] dataout_len How many data were actually signed (can be NULL)
*  \param [out] data_out Pointer to a pre-allocated buffer where to store the digest
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*/
uint16_t L1_digest(se3_session* s, uint16_t algorithm, size_t datain_len, uint8_t* data_in, size_t* dataout_len, uint8_t* data_out);
/**
*  \brief This function is used to retrieve a list from the device of available algorithms
*
*  \param [in] s Pointer to current se3_session, you must be logged in
*  \param [in] skip How many algorithms you want to skip from the beginning of the
*  			     device list
*  \param [in] max_algorithms How many algorithms you want to retrieve from the device
*  \param [out] algorithms_array Pointer to the already allocated array where to store the
*  			 				  algorithms
*  \param [in] count Effective number of retrieved keys
*  \return It returns SE3_OK on success, otherwise see \ref se3c1def.h
*
*/
uint16_t L1_get_algorithms(se3_session* s, uint16_t skip, uint16_t max_algorithms, se3_algo* algorithms_array, uint16_t* count);


#ifdef __cplusplus
}
#endif
