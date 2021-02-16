/**
 *  \file L0.h
 *  \brief This file contains L0 functions and structures
 *
 */

#pragma once

#include "se3_common.h"
#include "se3comm.h"
#include "crc16.h"


#ifdef __cplusplus
extern "C" {
#endif

/** \brief SEcube Device Information structure */
typedef struct se3_device_info_ {
    se3_char path[SE3_MAX_PATH];
    uint8_t serialno[SE3_SN_SIZE];
    uint8_t hello_msg[SE3_HELLO_SIZE];
    uint16_t status;
} se3_device_info;

/** \brief SEcube Device structure */
typedef struct se3_device_ {
    se3_device_info info;
    uint8_t* request;
    uint8_t* response;
	se3_file f;
    bool opened;
} se3_device;

/** \brief Discovery iterator */
typedef struct se3_disco_it_ {
    se3_device_info device_info;
    se3_drive_it _drive_it;
} se3_disco_it;

#ifdef CUBESIM
uint16_t L0_open_sim(se3_device* s);
#endif


/* defines */
#define SE3_NBLOCKS    (SE3_COMM_N-1)   // Number of blocks
#ifdef CUBESIM
#define SE3_TIMEOUT (1024*1024)
#else
#define SE3_TIMEOUT   (10000)
#endif

/* Sizes (in Bytes) */

#define SE3_RES_SIZE_HEADER   (32)

#define SE3_SIZE_PAYLOAD_MAX   ((SE3_COMM_BLOCK * SE3_NBLOCKS) - SE3_REQ_SIZE_HEADER - (SE3_COMM_BLOCK * SE3_REQDATA_SIZE_HEADER))
/* */

/**
 *  \brief Main function for communicating with SEcube device
 *  
 *  \param [in] device pointer to SEcube device structure
 *  \param [in] req_cmd Command to be executed
 *  \param [in] req_cmdflags Flag options for the command
 *  \param [in] req_len Length of the request
 *  \param [in] req_data array containing the request
 *  \param [in] resp_status Response status (received response or not)
 *  \param [in] resp_len Length of the response
 *  \param [in] resp_data array containing the response
 *  \return Error code or SE3_OK
 *  
 *  \details The function receive payload data from upper levels; segment the data and write it to the device.
 */
uint16_t L0_TXRX(se3_device* device, uint16_t req_cmd, uint16_t req_cmdflags, uint16_t req_len, const uint8_t* req_data, uint16_t* resp_status, uint16_t* resp_len, uint8_t* resp_data);

/**
 *  \brief Echo service 
 *  
 *  \param [in] device pointer to SEcube device structure
 *  \param [in] data_in Data to be sent
 *  \param [in] data_in_len Length of input data
 *  \param [in] data_out Data to be sent
 *  \return Error code or SE3_OK
 *  
 *  \details Details
 */
uint16_t L0_echo(se3_device* device, const uint8_t* data_in, uint16_t data_in_len, uint8_t* data_out);

/**
 *  \brief Initialise SEcube device
 *  
 *  \param [in] device pointer to SEcube device structure
 *  \param [in] serialno Serial Number to be set on SEcube device
 *  \return Error code or SE3_OK
 *  
 *  \details Before using the SEcube device, this function must be called. It can be used just once-
 */
uint16_t L0_factoryinit(se3_device* device, const uint8_t* serialno);

/**
 *  \brief Open SEcube device
 *  
 *  \param [in] dev pointer to SEcube device structure
 *  \param [in] dev_info Device Information structure
 *  \param [in] timeout timeout in ms
 *  \return Error code or SE3_OK
 *  
 */
uint16_t L0_open(se3_device* dev, se3_device_info* dev_info, uint32_t timeout);

/**
 *  \brief Close SEcube device
 *  
 *  \param [in] dev pointer to SEcube device structure
 *  \return Error code or SE3_OK
 *  
 */
void L0_close(se3_device* dev);

/**
 *  \brief Discover Serial Number information
 *  
 *  \param [in] serialno Serial Number of SEcube device
 *  \param [in] device pointer to SEcube device structure
 *  \return Error code or SE3_OK
 *  
 */
bool L0_discover_serialno(uint8_t* serialno, se3_device_info* device);

/**
 *  \brief Initialise discovery iterator
 *  
 *  \param [in] it iterator
 *  \return Error code or SE3_OK
 *  
 */
void L0_discover_init(se3_disco_it* it);

/**
 *  \brief Increment discovery iterator
 *  
 *  \param [in] it iterator
 *  \return Error code or SE3_OK
 *  
 *  \details Details
 */
bool L0_discover_next(se3_disco_it* it);

#ifdef __cplusplus
}
#endif
