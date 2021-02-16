/**
 *  \file se3_common.h
 *  \author Nicola Ferri, Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Common functions and data structures. Debug tools are also here
 */


#pragma once

#include "se3c1def.h"

extern const uint8_t se3_magic[SE3_MAGIC_SIZE];

#ifndef se3_serial_def
#define se3_serial_def
typedef struct SE3_SERIAL_ {
    uint8_t data[SE3_SERIAL_SIZE];
    bool written;  					///< Indicates whether the serial number has been set (by FACTORY_INIT)
} SE3_SERIAL;
#endif

/** \brief decoded request header */
typedef struct se3_comm_req_header_ {
    uint16_t cmd;
    uint16_t cmd_flags;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} se3_comm_req_header;

SE3_SERIAL serial;

uint16_t hwerror;

//########################DEBUG##############################
//#define SE3_DEBUG_SD

#ifdef SE3_DEBUG_SD

#define DATA_BASE_ADDRESS 41024

/** \brief creates the log file on the SEcube SD card
 *
 */
bool se3_create_log_file();

/** \brief flush the SEcube SD card blocks starting from the block start_address to the block end_address
 *
 */
bool se3_debug_sd_flush(uint32_t start_address, uint32_t end_address);

/** \brief write a trace on the log file in the specified address. N.B.: the string passed as parameter must be a function call to the
 * se3_debug_create_string function
 *
 */
bool se3_write_trace( char* buf, uint32_t blk_addr);

/** \brief prepare a correctly formatted string to be written with se3_write_trace function. N.B.: in order to get the best
 * 			readability, please insert before the string the '\n' character and a '\0' at the end of the string.
 *
 */
char* se3_debug_create_string(char * string);

/** \brief Global variable used to write the strings one after the other following a time line, in order to keep track
 * 		   of the temporal dependencies among the function calls. It will be initialised to DATA_BASE_ADDRESS and then
 * 		   incremented at each trace write operation.
 */
extern debug_address;

/*  DEBUG TOOL USAGE EXAMPLE:
 *
 * 1) If commented, de-comment '#define SE3_DEBUG_SD' in this file.
 * 2) Inside the device_init() function (se3_core.c file), add se3_create_log_file(); it will include a se3_debug_sd_flush() function call.
 * 3) Inside wherever you want, add se3_write_trace(se3_debug_create_string("\nHello World!\0"), debug_address++);
 * 4) Build your project and program the chip.
 * 5) Leave the device run for enough time, or launch some Host program. Then, your trace log file will contain the traces you programmed, if the code went right.
 */

#endif
//##############################################################

/**
 *  \brief Compute length of data in a request in terms of SE3_COMM_BLOCK blocks
 *  
 *  \param [in] len_data_and_headers Data length
 *  \return Number of SE3_COMM_BLOCK blocks
 *  
 */
uint16_t se3_req_len_data(uint16_t len_data_and_headers);

/**
 *  \brief Compute length of data in a request accounting for headers
 *  
 *  \param [in] len_data Data length
 *  \return Number of Bytes
 *  
 */
uint16_t se3_req_len_data_and_headers(uint16_t len_data);

/**
 *  \brief Compute length of data in a request in terms of SE3_COMM_BLOCK blocks
 *  
 *  \param [in] len_data_and_headers Data length
 *  \return Number of SE3_COMM_BLOCK blocks
 *  
 */
uint16_t se3_resp_len_data(uint16_t len_data_and_headers);

/**
 *  \brief Compute length of data in a response accounting for headers
 *  
 *  \param [in] len_data Data Length
 *  \return Number of Bytes
 *  
 */
uint16_t se3_resp_len_data_and_headers(uint16_t len_data);

/**
 *  \brief Compute number of SE3_COMM_BLOCK blocks, given length in Bytes
 *  
 *  \param [in] cap Length
 *  \return Number of Blocks
 *  
 */
uint16_t se3_nblocks(uint16_t len);






