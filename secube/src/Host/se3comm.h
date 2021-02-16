#pragma once
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <malloc.h>
#include <fcntl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "se3c0def.h"

#ifdef _DEBUG
#include <stdio.h>
#define se3_trace(msg) printf msg
#else
#define se3_trace(msg)
#endif
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <string.h>

#define SE3_SN_SIZE (32)

#ifdef _WIN32
    typedef struct {
        OVERLAPPED ol;
        HANDLE h;
    } se3_file;
    typedef wchar_t se3_char;
#define SE3_MAGIC_FILE (L".se3magic")
#define SE3_OSSEP (L'\\')
#define SE3_MAX_PATH (256)
#else
    typedef struct {
        int fd;
        void* buf; //[512] memalign
        bool locked;
    } se3_file;
    typedef char se3_char;
#define SE3_MAGIC_FILE (".se3magic")
#define SE3_OSSEP ('/')
#define SE3_MAX_PATH (256)
#endif

#define SE3_MAGIC_FILE_LEN (9)

	typedef struct se3_discover_info_ {
		uint8_t serialno[SE3_SERIAL_SIZE];
		uint8_t hello_msg[SE3_HELLO_SIZE];
		uint16_t status;
	} se3_discover_info;

#define SE3_DRIVE_BUF_MAX (1024)


    typedef struct se3_drive_it_ {
        se3_char* path;

        se3_char buf_[SE3_DRIVE_BUF_MAX + 1];
        size_t buf_len_;
#ifdef _WIN32
        size_t pos_;
#else
        FILE* fp_;
#endif
    } se3_drive_it;

    void se3c_rand(size_t len, uint8_t* buf);

    void se3c_drive_init(se3_drive_it* it);
    bool se3c_drive_next(se3_drive_it* it);

    bool se3c_write(uint8_t* buf, se3_file hfile, size_t block, size_t size, uint32_t timeout);
    bool se3c_read(uint8_t* buf, se3_file hfile, size_t block, size_t size, uint32_t timeout);
    bool se3c_info(se3_char* path, uint64_t deadline, se3_discover_info* info);
    bool se3c_open(se3_char* path, uint64_t deadline, se3_file* phfile, se3_discover_info* disco);
    void se3c_close(se3_file hfile);
    //bool se3c_flock_acquire(se3_file hfile, clock_t deadline);
    //void se3c_flock_release(se3_file hfile);
    uint64_t se3c_deadline(uint32_t timeout);
    void se3c_pathcopy(se3_char* dest, se3_char* src);
    uint64_t se3c_clock();

#ifdef _WIN32
#define se3c_sleep() Sleep(0)
#else
#define se3c_sleep() usleep(1000)
#endif

#define SE3C_MAGIC_TIMEOUT (1000)

#ifdef __cplusplus
}
#endif



