
#include "stubs.h"
#include "se3_flash.h"

int32_t secube_sdio_write(uint8_t lun, const uint8_t* buf, uint32_t blk_addr, uint16_t blk_len)
{
	return 0;
}
int32_t secube_sdio_read(uint8_t lun, uint8_t* buf, uint32_t blk_addr, uint16_t blk_len)
{
	return 0;
}


static keyStr keys[20];
static int keyvalid[20];
static HANDLE  mutex;

void stubs_init()
{
	mutex = CreateMutexW(NULL, FALSE, NULL);
	flash_init();
}

void sim_mutex_acquire()
{
	WaitForSingleObject(mutex, INFINITE);
}
void sim_mutex_release()
{
	ReleaseMutex(mutex);
}


int32_t se3_rand(uint16_t size, uint8_t* data)
{
	size_t i;
	srand((unsigned)time(0));
	for (i = 0; i < size; i++)
	{
		data[i] = (uint8_t)rand();
	}
	return size;
}



uint8_t* stub_flash = NULL;

static void flash_init()
{
	HANDLE hFile, hMap;
	hFile = CreateFileW(L"flash.bin", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	hMap = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 2 * SE3_FLASH_SECTOR_SIZE, NULL);
	stub_flash = (uint8_t*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 2 * SE3_FLASH_SECTOR_SIZE);
}

HAL_StatusTypeDef HAL_FLASH_Unlock()
{
	if (stub_flash == NULL)flash_init();
	return HAL_OK;
}
HAL_StatusTypeDef HAL_FLASH_Lock()
{
	BOOL ok = FlushViewOfFile((void*)stub_flash, 0);
	return HAL_OK;
}
HAL_StatusTypeDef HAL_FLASH_Program(uint32_t TypeProgram, uint32_t Address, uint64_t Data)
{
	size_t i;
	for (i = 0; i < (size_t)(1 << TypeProgram); i++)
	{
		*((uint8_t*)(Address + i)) &= *(((uint8_t*)&Data) + i);
	}
	return HAL_OK;
}

void sim_clear_flash()
{
	se3_flash_info_setup((uint32_t)SE3_FLASH_S0, (uint8_t*)SE3_FLASH_S0_ADDR);
	memset(stub_flash, 0xFF, 2*SE3_FLASH_SECTOR_SIZE);
	memcpy(stub_flash, se3_magic, SE3_FLASH_MAGIC_SIZE);

}

size_t sim_get_allocated_mem()
{
	return se3c0.flash.allocated;
}