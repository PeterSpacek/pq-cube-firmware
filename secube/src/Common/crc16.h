/**
 *  \file crc16.h
 *  \brief This file contains defines and functions for computing CRC
 */

#pragma once

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

	extern const uint16_t se3_crc16_table[0x100];
	
	/**
	 *  \brief Compute CRC
	 *  
	 *  \param [in] length Data length
	 *  \param [in] data Data on which CRC is computed
	 *  \param [in] crc CRC
	 *  \return CRC computed
	 *  
	 */
	uint16_t se3_crc16_update(size_t length, const uint8_t* data, uint16_t crc);

#ifdef __cplusplus
}
#endif
