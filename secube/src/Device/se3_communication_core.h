/**
 *  \file se3_communication_core.h
 *  \author Nicola Ferri
 *  \co-author Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief USB read/write handlers
 */

#pragma once

#include "se3_common.h"


#define SE3_BMAP_MAKE(n) ((uint32_t)(0xFFFFFFFF >> (32 - (n))))


/** \brief structure holding host-device communication status and buffers
 *
 *  req_ready and resp_ready must be volatile, otherwise -O3 optimization will not work.
 */
typedef struct SE3_COMM_STATUS_ {
    // magic
    bool magic_ready;  ///< magic written flag
    uint32_t magic_bmap;  ///< bit map of written magic sectors

    // block map
    uint32_t blocks[SE3_COMM_N];  ///< map of blocks
    uint32_t block_guess;  ///< guess for next block that will be accessed
    bool locked;  ///< prevent magic initialization

    // request
    volatile bool req_ready;  ///< request ready flag
    uint32_t req_bmap;  ///< map of received request blocks
    uint8_t* req_data;  ///< received data buffer
    uint8_t* req_hdr;   ///< received header buffer

    // response
    volatile bool resp_ready;  ///< response ready flag
    uint32_t resp_bmap;  ///< map of sent response blocks
    uint8_t* resp_data;  ///< buffer for data to be sent
    uint8_t* resp_hdr;  ///< buffer for header to be sent
} SE3_COMM_STATUS;


/** \brief response header to be encoded */
typedef struct se3_comm_resp_header_ {
    uint16_t ready;
    uint16_t status;
    uint16_t len;
#if SE3_CONF_CRC
    uint16_t crc;
#endif
    uint32_t cmdtok[SE3_COMM_N - 1];
} se3_comm_resp_header;

/** USB data handlers return values */
enum {
	SE3_PROTO_OK = 0,  ///< Report OK to the USB HAL
	SE3_PROTO_FAIL = 1,  ///< Report FAIL to the USB HAL
	SE3_PROTO_BUSY = 2  ///< Report BUSY to the USB HAL
};

SE3_COMM_STATUS comm;
se3_comm_req_header req_hdr;
se3_comm_resp_header resp_hdr;
const uint8_t se3_hello[SE3_HELLO_SIZE];



/**\brief Initializes the communication core structures */
void se3_communication_core_init();


/** \brief USB data receive handler
 *  
 *  SEcube API requests are filtered and data is stored in the request buffer.
 *  The function also takes care of the initialization of the special protocol file.
 *  Other requests are passed to the SDIO interface.
 */
int32_t se3_proto_recv(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);

/** \brief USB data send handler
 *   
 *  SEcube API requests are filtered and data is sent from the response buffer
 *  Other requests are passed to the SDIO interface.
 */
int32_t se3_proto_send(uint8_t lun, uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);



