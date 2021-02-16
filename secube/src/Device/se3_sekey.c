#include "se3_sekey.h"

/*	sekey_get_implementation_info: This function would be the core of the sekey behavior,
 * 	it has to be implemented. The provided code is just a stub
 */


bool sekey_get_implementation_info(uint8_t* algo_implementation, uint8_t* crypto_algo, uint8_t *key){

	if (sekey_get_auth(key)){
		*algo_implementation = SE3_SECURITY_CORE;
		*crypto_algo = SE3_AES256;
	}
	return true;
}

bool sekey_get_auth(uint8_t *key){

	return true;
}
