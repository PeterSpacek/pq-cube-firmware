/**
 *  \file se3_core_time.h
 *  \author Nicola Ferri
 *  \co-author Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Core Timer
 */

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "sha256.h"
#include "aes256.h"
#include "se3c0def.h"
#include "se3_common.h"


/** \brief Initializes timer */
void se3_time_init();

/** \brief Returns the current time */
uint64_t se3_time_get();

/** \brief Sets current time with t */
void se3_time_set(uint64_t t);

/** \brief Increments the current time of 1 s  */
void se3_time_inc();

/** \brief Returns true if the time was initialized */
bool get_now_initialized();
