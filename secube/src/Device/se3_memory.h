/**
 *  \file se3_memory.h
 *  \author Nicola Ferri
 *  \brief Memory management (session allocator)
 */

#pragma once
#include "se3_core_time.h"
#include <stdbool.h>
/** \brief memory allocator structure */
typedef struct se3_mem_ {
	size_t max_count;
	uint8_t** ptr;
	uint8_t* dat;
	size_t dat_size;
	size_t used;
} se3_mem;

enum {
	SE3_MEM_HEADER = 4,  ///< entry header size
	SE3_MEM_BLOCK = 32  ///< memory alignment
};

/** \brief initialize memory allocator
 *  \param mem memory buffer object
 *  \param index_size number of elements in index
 *  \param index pointer to the index buffer (array[index_size] of pointers)
 *  \param buf_size number of bytes in data buffer
 *  \param buf pointer to data buffer
 */
void se3_mem_init(se3_mem* mem, size_t index_size, uint8_t** index, size_t buf_size, uint8_t* buf);

/** \brief allocate one entry
 *
 *  \param mem memory buffer object
 *  \param size allocation size
 */
int32_t se3_mem_alloc(se3_mem* mem, size_t size);

/** \brief get pointer to entry in buffer
 *
 *  \param mem memory buffer object
 *  \param id of the entry
 */
uint8_t* se3_mem_ptr(se3_mem* mem, int32_t id);

/** \brief release single entry
 *
 *  \param mem memory buffer object
 *  \param id of the entry
 */
void se3_mem_free(se3_mem* mem, int32_t id);

/** \brief release all entries
*
*  \param mem memory buffer object
*/
void se3_mem_reset(se3_mem* mem);
