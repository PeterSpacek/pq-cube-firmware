/**
 *  \file se3_keys.c
 *  \author Nicola Ferri
 *  \brief Key management
 */

#include "se3_keys.h"

enum {
	SE3_KEY_OFFSET_ID = 0,
	SE3_KEY_OFFSET_VALIDITY = 4,
	SE3_KEY_OFFSET_DATALEN = 8,
	SE3_KEY_OFFSET_NAMELEN = 10,
	SE3_KEY_OFFSET_DATA = 12
};

bool se3_key_find(uint32_t id, se3_flash_it* it)
{
    uint32_t key_id = 0;
	se3_flash_it_init(it);
	while (se3_flash_it_next(it)) {
		if (it->type == SE3_TYPE_KEY) {
            SE3_GET32(it->addr, SE3_KEY_OFFSET_ID, key_id);
			if (key_id == id) {
				return true;
			}
		}
	}
	return false;
}

bool se3_key_remove(se3_flash_it* it)
{
	if (!se3_flash_it_delete(it)) {
		SE3_TRACE(("E key_remove cannot free flash block\n"));
		return false;
	}
	return true;
}

bool se3_key_new(se3_flash_it* it, se3_flash_key* key)
{
	uint16_t size = (SE3_FLASH_KEY_SIZE_HEADER + key->data_size + key->name_size);
    if (size > SE3_FLASH_NODE_DATA_MAX) {
        return false;
    }
	if (!se3_flash_it_new(it, SE3_TYPE_KEY, size)) {
		SE3_TRACE(("E key_new cannot allocate flash block\n"));
		return false;
	}
	return se3_key_write(it, key);
}

void se3_key_read(se3_flash_it* it, se3_flash_key* key)
{
    SE3_GET32(it->addr, SE3_KEY_OFFSET_ID, key->id);
    SE3_GET32(it->addr, SE3_KEY_OFFSET_VALIDITY, key->validity);
    SE3_GET16(it->addr, SE3_KEY_OFFSET_DATALEN, key->data_size);
    SE3_GET16(it->addr, SE3_KEY_OFFSET_NAMELEN, key->name_size);

	if (key->data) {
		memcpy(key->data, it->addr + 12, key->data_size);
	}
	if (key->name) {
		memcpy(key->name, it->addr + 12 + key->data_size, key->name_size);
	}
}

bool se3_key_equal(se3_flash_it* it, se3_flash_key* key)
{
	uint32_t u32tmp = 0;
	uint16_t u16tmp = 0;
	
	if (key->name == NULL)return false;
	if (key->data == NULL)return false;
	
	SE3_GET32(it->addr, SE3_KEY_OFFSET_ID, u32tmp);
	if (u32tmp != key->id) return false;
	SE3_GET32(it->addr, SE3_KEY_OFFSET_VALIDITY, u32tmp);
	if (u32tmp != key->validity) return false;
	SE3_GET16(it->addr, SE3_KEY_OFFSET_DATALEN, u16tmp);
	if (u16tmp != key->data_size) return false;
	SE3_GET16(it->addr, SE3_KEY_OFFSET_NAMELEN, u16tmp);
	if (u16tmp != key->name_size) return false;

	if (memcmp(it->addr + SE3_KEY_OFFSET_DATA, key->data, key->data_size)) {
		return false;
	}
	if (memcmp(it->addr + SE3_KEY_OFFSET_DATA + key->data_size, key->name, key->name_size)) {
		return false;
	}
	return true;
}

void se3_key_read_data(se3_flash_it* it, uint16_t data_size, uint8_t* data)
{
	memcpy(data, it->addr + 12, data_size);
}

bool se3_key_write(se3_flash_it* it, se3_flash_key* key)
{
	uint8_t tmp[4];
	bool success = false;
	do {
		if (!se3_flash_it_write(it, 0, (uint8_t*)&(key->id), 4)) {
			break;
		}
		if (!se3_flash_it_write(it, 4, (uint8_t*)&(key->validity), 4)) {
			break;
		}
        SE3_SET16(tmp, 0, key->data_size);
        SE3_SET16(tmp, 2, key->name_size);
		if (!se3_flash_it_write(it, 8, tmp, 4)) {
			break;
		}

		if (key->data_size) {
			if (!se3_flash_it_write(it, 12, key->data, key->data_size)) {
				break;
			}
		}
		if (key->name_size) {
			if (!se3_flash_it_write(it, 12 + key->data_size, key->name, key->name_size)) {
				break;
			}
		}
		success = true;
	} while (0);

	if (!success) {
        SE3_TRACE(("[se3_key_write] cannot write to flash block\n"));
	}
	return success;
}

void se3_key_fingerprint(se3_flash_key* key, const uint8_t* salt, uint8_t* fingerprint)
{
	PBKDF2HmacSha256(key->data, key->data_size, salt, SE3_KEY_SALT_SIZE, 1, fingerprint, SE3_KEY_FINGERPRINT_SIZE);
}
