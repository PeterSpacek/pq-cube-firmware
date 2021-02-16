#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define SD_DATATIMEOUT ((uint32_t)100000000)
#define MEM_OP_FAIL (1)
#define MEM_OP_OK (0)
#define STORAGE_LUN_NBR (1)
#define STORAGE_BLK_SIZ (512)

bool secube_sdio_read(uint8_t lun, uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);
bool secube_sdio_write(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);
bool secube_sdio_capacity(uint32_t *block_num, uint16_t *block_size);
bool secube_sdio_isready(void);

