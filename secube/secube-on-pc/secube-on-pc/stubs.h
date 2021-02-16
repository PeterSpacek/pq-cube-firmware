#pragma once

#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int32_t secube_sdio_read(uint8_t lun, uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);
int32_t secube_sdio_write(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len);


typedef struct {
	int32_t keyId;
	int8_t keyLabel[16];
	uint16_t keyLen;
	int32_t val;
	uint8_t* key;
} keyStr;


int32_t se3_rand(uint16_t size, uint8_t* data);


typedef enum
{
	HAL_OK = 0x00U,
	HAL_ERROR = 0x01U,
	HAL_BUSY = 0x02U,
	HAL_TIMEOUT = 0x03U
} HAL_StatusTypeDef;

#define FLASH_TYPEPROGRAM_BYTE        ((uint32_t)0x00U)  /*!< Program byte (8-bit) at a specified address           */
#define FLASH_TYPEPROGRAM_HALFWORD    ((uint32_t)0x01U)  /*!< Program a half-word (16-bit) at a specified address   */
#define FLASH_TYPEPROGRAM_WORD        ((uint32_t)0x02U)  /*!< Program a word (32-bit) at a specified address        */
#define FLASH_TYPEPROGRAM_DOUBLEWORD  ((uint32_t)0x03U)  /*!< Program a double word (64-bit) at a specified address */

extern uint8_t* stub_flash;
#define SE3_FLASH_SECTOR_SIZE (128*1024)
#define SE3_FLASH_S0  (10)
#define SE3_FLASH_S1  (11)
#define SE3_FLASH_S0_ADDR ((uint32_t)(stub_flash+0*SE3_FLASH_SECTOR_SIZE))
#define SE3_FLASH_S1_ADDR ((uint32_t)(stub_flash+1*SE3_FLASH_SECTOR_SIZE))


HAL_StatusTypeDef HAL_FLASH_Unlock();
HAL_StatusTypeDef HAL_FLASH_Lock();
HAL_StatusTypeDef HAL_FLASH_Program(uint32_t TypeProgram, uint32_t Address, uint64_t Data);




void stubs_init();
void flash_init();
void sim_mutex_acquire();
void sim_mutex_release();
void sim_clear_flash();
size_t sim_get_allocated_mem();


#define USBD_OK 0
#define USBD_FAIL 1
#define USBD_BUSY 2
#define BLOCK_SIZE 512


