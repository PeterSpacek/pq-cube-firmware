/**
 *  \file pbdkdf2.h
 *  \brief This file contains defines and functions for PBDKDF2 (Password-Based 
 *         Key Derivation Function 2)
 */

#pragma once

#include <stdint.h>
#include <string.h>

#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 *  \brief Public Key Derivation Function 2
	 *  
	 *  \param [in] pw Master password
	 *  \param [in] npw Length of Master password
	 *  \param [in] salt Salt
	 *  \param [in] nsalt Length of Salt
	 *  \param [in] iterations Number of iterations
	 *  \param [in] out Pointer to output
	 *  \param [in] nout Length of ouput
	 *  
	 */
	void PBKDF2HmacSha256(
		const uint8_t *pw, size_t npw,
		const uint8_t *salt, size_t nsalt,
		uint32_t iterations,
		uint8_t *out, size_t nout);

#ifdef __cplusplus
}
#endif
