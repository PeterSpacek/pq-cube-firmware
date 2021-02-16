/**
 *  \file se3_core.h
 *  \author Nicola Ferri
 *  \co-author Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Main Core
 */
#pragma once


#include <se3c0def.h>


#if defined(_MSC_VER)
#define SE3_ALIGN_16 __declspec(align(0x10))
#elif defined(__GNUC__)
#define SE3_ALIGN_16 __attribute__((aligned(0x10)))
#else
#define SE3_ALIGN_16
#endif



/** \brief Initialise the device modules
 *
 * Initialise the main cores and data structures
 */
void device_init();


/** \brief Endless loop that executes the commands
 *
 * 	This function stays in idle waiting for command and data transfer requests
 */
void device_loop();


/** \brief Execute received command
 *
 *  Process the last received request and produce a response
 */
void se3_cmd_execute();


/** \brief ECHO command handler
 *
 *  Send back received data
 */
uint16_t echo(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);

/** \brief FACTORY_INIT command handler
 *
 *  Initialize device's serial number
 */
uint16_t factory_init(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);


/** \brief FACTORY_INIT command handler
 *
 *  Reset USEcube to boot mode
 */
uint16_t bootmode_reset(uint16_t req_size, const uint8_t* req, uint16_t* resp_size, uint8_t* resp);
