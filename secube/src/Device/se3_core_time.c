/**
 *  \file se3_core_time.c
 *  \author Nicola Ferri
 *  \co-author Filippo Cottone, Pietro Scandale, Francesco Vaiana, Luca Di Grazia
 *  \brief Core Timer
 */

#include "se3_core_time.h"

uint64_t now;  ///< current UNIX time in seconds
bool now_initialized;  ///< time was initialized
int flag = 1;

void se3_time_init(){
	now_initialized = false;
	now = 0;
}

uint64_t se3_time_get()
{
#ifdef CUBESIM
    now = (uint64_t)time(0);
#endif
    return now;
}

void se3_time_set(uint64_t t)
{
    now = t;
	now_initialized = true;
}

void se3_time_inc()
{
    static unsigned int ms = 0;
    if (++ms == 1000) {
    	flag = 0;
        (now)++;
        ms = 0;
    }
}

bool get_now_initialized(){
	return now_initialized;
}

