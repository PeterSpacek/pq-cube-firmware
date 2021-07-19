/**
 *  \file se3_keys.h
 *  \author Nicola Ferri
 *  \brief Key management
 */

#pragma once
#include "se3c1def.h"
#include "se3_flash.h"
#include "pbkdf2.h"
#define SE3_TYPE_KEY 100

#define SE3_KEYPAIR_ID_OFFSET 32768
#define SE3_KEYS_ID_OFFSET 65536

/** \brief Flash key structure
 *  
 *  Disposition of the fields within the flash node:
 *  0:3     id
 *  4:7     validity
 *  8:9     data_size
 *  10:11   name_size
 *  12:(12+data_size-1)
 *          data
 *  (12+data_size):(12+data_size+name_size-1)
 *          name
 */
typedef struct se3_flash_key_ {
	uint32_t id;
	uint32_t validity;
	uint16_t data_size;
	uint16_t name_size;
	uint8_t* data;
	uint8_t* name;
} se3_flash_key;

/** Flash key fields */
enum {
    SE3_FLASH_KEY_OFF_ID = 0,
    SE3_FLASH_KEY_OFF_VALIDITY = 4,
    SE3_FLASH_KEY_OFF_DATA_LEN = 8,
    SE3_FLASH_KEY_OFF_NAME_LEN = 10,
    SE3_FLASH_KEY_OFF_NAME_AND_DATA = 12,

    SE3_FLASH_KEY_SIZE_HEADER = SE3_FLASH_KEY_OFF_NAME_AND_DATA
};

/** \brief Find a key
 *
 *  Find a key in the flash memory
 *  \param id identifier of the key
 *  \param it a flash iterator that will be set to the key's position
 *  \return true on success
 */
bool se3_key_find(uint32_t id, se3_flash_it* it);

/** \brief Remove a key
 *  
 *  Delete a key from the flash
 *  \remark if a flash operation fails, the hwerror flag (se3c0.hwerror) is set.
 *  \param it a flash iterator pointing to the key
 *  \return true on success
 */
bool se3_key_remove(se3_flash_it* it);

/** \brief Add a new key
 *  
 *  Create a new node with the necessary amount of space for the key,
 *  then write the key.
 *  \remark if a flash operation fails, the hwerror flag (se3c0.hwerror) is set.
 *  \param it a flash iterator which will receive the position of the new node
 *  \param key a flash key structure containing the key information
 *      The data and name fields must point to a valid memory region,
 *      unless their size (data_size, name_size) is zero.
 *  \return true on success, else false
 */
bool se3_key_new(se3_flash_it* it, se3_flash_key* key);

/** \brief Read a key
 *  
 *  Read a key from a flash node
 *  \param it a flash iterator pointing to the key
 *  \param key a flash key structure which will receive the key's information. 
 *      The data and name fields will be filled only if not NULL.
 */
void se3_key_read(se3_flash_it* it, se3_flash_key* key);

/** \brief Check if key is equal
 *  
 *  Check if the supplied key is equal to a key stored in the flash.
 *  \param it a flash iterator pointing to a key
 *  \param key a flash key structure to compare
 *  \return true if equal, else false
 */
bool se3_key_equal(se3_flash_it* it, se3_flash_key* key);

/** \brief Read data from key node
 *  
 *  Read the key's data from a ket node
 *  \param it a flash iterator pointing to the key
 *  \param data_size the number of bytes to read
 *  \param data output data buffer
 */
void se3_key_read_data(se3_flash_it* it, uint16_t data_size, uint8_t* data);

/** \brief Write key data
 *  
 *  Write key data to a flash node
 *  \remark if a flash operation fails, the hwerror flag (se3c0.hwerror) is set.
 *  \param it a flash iterator pointing to a newly created flash node of key type
 *  \param key a flash key structure containing the key information
 *      The data and name fields must point to a valid memory region,
 *      unless their size (data_size, name_size) is zero.
 *  \return true on success, else false
 */
bool se3_key_write(se3_flash_it* it, se3_flash_key* key);

/** \brief Produce salted key fingerprint
 *  
 *  \param key a flash key structure containing the key information
 *  \param salt a 32-byte salt
 *  \param fingerprint output 32-byte fingerprint of the key data
 */
void se3_key_fingerprint(se3_flash_key* key, const uint8_t* salt, uint8_t* fingerprint);





