/**
 *  \file se3_dispatcher_core.h
 *  \author Nicola Ferri
 *  \co-author Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Dispatcher core
 */

#include "se3_security_core.h"
#include "se3_keys.h"
#include "se3_common.h"
#include "se3_rand.h"
#include "se3_sekey.h"

#define SE3_CMD1_MAX 	16
#define SE3_N_HARDWARE 	3

/** \brief login status data */
typedef struct SE3_LOGIN_STATUS_ {
    bool y;  ///< logged in
    uint16_t access;  ///< access level
    uint16_t challenge_access;  ///< access level of the last offered challenge
    union {
        uint8_t token[SE3_TOKEN_SIZE];   ///< login token
        uint8_t challenge[SE3_CHALLENGE_SIZE];  ///< login challenge response expected
    };
    uint8_t key[SE3_KEY_SIZE];  ///< session key for protocol encryption
    se3_payload_cryptoctx cryptoctx;  ///< context for protocol encryption
    bool cryptoctx_initialized;  ///< context initialized flag
} SE3_LOGIN_STATUS;

/** \brief Contains the useful status data for login operations. */
SE3_LOGIN_STATUS login_struct;

/** \brief Security function prototype. */
typedef uint16_t(*se3_cmd_func)(uint16_t, const uint8_t*, uint16_t*, uint8_t*);

/** \brief Set or get configuration record from the request buffer. */
uint16_t config(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief KEY_EDIT
 *
 *  Insert, delete or update a key
 */
uint16_t key_edit(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief KEY_LIST
 *
 *  Get a list of keys in the device
 */
uint16_t key_list(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief CHALLENGE command handler
 *
 *  Get a login challenge from the device
 */
uint16_t challenge(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief LOGIN command handler
 *
 *  Respond to challenge and complete the login
 */
uint16_t login(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief LOGOUT command handler
 *
 *  Log out and release resources
 */
uint16_t logout(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Handler for invalid command request. */
uint16_t error(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Executes a security function, by using the implementation chosen by SEkey. */
uint16_t dispatcher_call(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief Clear login session data
 *
 *  Cleans all data associated with the login session, making SEcube ready for a new login.
 */

/** \brief Initialize structures */
void se3_dispatcher_init();

/** \brief sets the req\_hdr data structure to the structure passed as parameter; */
void set_req_hdr(se3_comm_req_header req_hdr_i);

/** \brief Table of function where all the possible operation of SECube are stored.
 *  It it organized as a matrix where at each row corresponds a
 *  different hardware or software implementation.
 */
static se3_cmd_func handlers[SE3_N_HARDWARE][SE3_CMD1_MAX] = {{
//Security Core
    /* 0  */ NULL,
    /* 1  */ challenge,
    /* 2  */ login,
    /* 3  */ logout,
    /* 4  */ config,
    /* 5  */ key_edit,
    /* 6  */ key_list,
    /* 7  */ crypto_init,
    /* 8  */ crypto_update,
    /* 9  */ crypto_list,
    /* 10 */ crypto_set_time,
    /* 11 */ crypto_kem_keypair,
    /* 12 */ crypto_kem_enc,
    /* 13 */ crypto_kem_dec,
    /* 14 */ NULL,
    /* 15 */ error
}, {
//FPGA: when developed, the function will have to be added here
    /* 0  */ NULL,
    /* 1  */ NULL,
    /* 2  */ NULL,
    /* 3  */ NULL,
    /* 4  */ NULL,
    /* 5  */ NULL,
    /* 6  */ NULL,
    /* 7  */ NULL,
    /* 8  */ NULL,
    /* 9  */ NULL,
    /* 10 */ NULL,
    /* 11 */ NULL,
    /* 12 */ NULL,
    /* 13 */ NULL,
    /* 14 */ NULL,
    /* 15 */ NULL
}, {
//Smartcard: when developed, the function will have to be added here
    /* 0  */ NULL,
    /* 1  */ NULL,
    /* 2  */ NULL,
    /* 3  */ NULL,
    /* 4  */ NULL,
    /* 5  */ NULL,
    /* 6  */ NULL,
    /* 7  */ NULL,
    /* 8  */ NULL,
    /* 9  */ NULL,
    /* 10 */ NULL,
    /* 11 */ NULL,
    /* 12 */ NULL,
    /* 13 */ NULL,
    /* 14 */ NULL,
    /* 15 */ NULL
}};




