#include "se3comm.h"
#include "se3_common.h"

#define _GNU_SOURCE
#ifndef O_DIRECT
#define O_DIRECT 00040000 /* direct disk access hint */
#endif

#ifdef _WIN32
#pragma warning(disable:4996)
#pragma comment(lib, "Advapi32.lib")
typedef BOOL(WINAPI *tADVAPI32_CryptAcquireContextW)(
	ULONG_PTR  *phProv,
	LPCWSTR    szContainer,
	LPCWSTR    szProvider,
	DWORD       dwProvType,
	DWORD       dwFlags);
typedef BOOL(WINAPI *tADVAPI32_CryptGenRandom)(
	ULONG_PTR  hProv,
	DWORD   dwLen,
	BYTE    *pbBuffer);
typedef BOOL(WINAPI *tADVAPI32_CryptReleaseContext)(
	ULONG_PTR  hProv,
	DWORD       dwFlags);
enum {
	ADVAPI32_PROV_RSA_FULL = 1,
	ADVAPI32_CRYPT_NEWKEYSET = 0x00000008,
	ADVAPI32_NTE_BAD_KEYSET = _HRESULT_TYPEDEF_(0x80090016L)
};
#endif

enum {
	SE3C_OK = 0,
	SE3C_ERR_NOT_FOUND = 1,
	SE3C_ERR_TIMEOUT = 2,
	SE3C_ERR_NO_DEVICE = 3
};

#ifndef ERROR_FILE_CHECKED_OUT
#define ERROR_FILE_CHECKED_OUT (220L)
#endif
#ifndef FSCTL_IS_VOLUME_MOUNTED
#define FSCTL_IS_VOLUME_MOUNTED (0x90028)
#endif

void se3c_rand(size_t len, uint8_t* buf) {
#ifdef _WIN32
	HMODULE hAdvapi32 = NULL;
	tADVAPI32_CryptAcquireContextW ADVAPI32_CryptAcquireContextW = NULL;
	tADVAPI32_CryptGenRandom ADVAPI32_CryptGenRandom = NULL;
	tADVAPI32_CryptReleaseContext ADVAPI32_CryptReleaseContext = NULL;
	bool wincrypt_available = false;
	ULONG_PTR hProvider = 0;

	if (!hAdvapi32) {
		hAdvapi32 = LoadLibraryW(L"Advapi32.dll");
		if (hAdvapi32 != NULL) {
			ADVAPI32_CryptAcquireContextW = (tADVAPI32_CryptAcquireContextW)GetProcAddress(hAdvapi32, "CryptAcquireContextW");
			ADVAPI32_CryptGenRandom = (tADVAPI32_CryptGenRandom)GetProcAddress(hAdvapi32, "CryptGenRandom");
			ADVAPI32_CryptReleaseContext = (tADVAPI32_CryptReleaseContext)GetProcAddress(hAdvapi32, "CryptReleaseContext");
			if (ADVAPI32_CryptAcquireContextW != NULL &&  ADVAPI32_CryptGenRandom != NULL && ADVAPI32_CryptReleaseContext != NULL) {
				wincrypt_available = true;
			}
		}
	}

	if (wincrypt_available) {
		if (FALSE == ADVAPI32_CryptAcquireContextW(&hProvider, NULL, NULL, ADVAPI32_PROV_RSA_FULL, 0)) {
			if (ADVAPI32_NTE_BAD_KEYSET == GetLastError()) {
				if (FALSE == ADVAPI32_CryptAcquireContextW(&hProvider, NULL, NULL, ADVAPI32_PROV_RSA_FULL, ADVAPI32_CRYPT_NEWKEYSET)) {
					hProvider = 0;
				}
			}
		}
	}

	if (hProvider != 0) {
		ADVAPI32_CryptGenRandom(hProvider, (DWORD)len, buf);
		ADVAPI32_CryptReleaseContext(hProvider, 0U);
	}
	else {
		for (size_t i = 0; i < len; i++) {
			buf[i] = (uint8_t)rand();
		}
	}

#else
	int frnd = open("/dev/urandom", O_RDONLY);
	read(frnd, buf, len);
	close(frnd);
#endif
}

#ifdef _WIN32
static bool se3c_win32_disk_in_drive(wchar_t* path)
{
    /*
    Source: https://social.msdn.microsoft.com/Forums/vstudio/en-US/18ef7c0b-2dab-40e6-aae8-9fbf55cb8686/how-to-detect-if-there-is-a-disk-in-the-drive?forum=vcgeneral
    */
    wchar_t volume[MAX_PATH];
	DWORD bytesReturned; // ignored
	BOOL devSuccess;
	HANDLE h;
	DWORD lastError;
	
    wcscpy(volume, L"\\\\.\\");
    wcsncat(volume, path, 2);

    h = CreateFileW(
        volume,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (h == INVALID_HANDLE_VALUE)
    {
        lastError = GetLastError();
        return (lastError != 2) ? (true) : (false);
    }

    devSuccess = DeviceIoControl(h, FSCTL_IS_VOLUME_MOUNTED, NULL, 0, NULL, 0, &bytesReturned, NULL);

    if (devSuccess == FALSE)
    {
        lastError = GetLastError();
        CloseHandle(h);
        return false;
    }

    CloseHandle(h);
    return true;
}


void se3c_drive_init(se3_drive_it* it)
{
    it->buf_len_ = GetLogicalDriveStringsW(SE3_DRIVE_BUF_MAX, it->buf_);
    it->buf_[it->buf_len_] = L'\0';
    it->path = NULL;
}

bool se3c_drive_next(se3_drive_it* it)
{
    bool found = false;
    while (!found) {
        if (it->path == NULL) {
            if (it->buf_len_ == 0)return false;
            it->path = it->buf_;
        }
        else {
            while (it->path < it->buf_ + it->buf_len_ && *(it->path) != L'\0') {
                (it->path)++;
            }
            (it->path)++;
            if (it->path >= it->buf_ + it->buf_len_) {
                return false;
            }
        }
        if (se3c_win32_disk_in_drive(it->path)) {
            if (GetDriveTypeW(it->path) == DRIVE_REMOVABLE) {
                found = true;
            }
        }
    }
    return true;
}



bool se3c_write(uint8_t* buf, se3_file hfile, size_t block, size_t nblocks, uint32_t timeout)
{
    bool success = false;
    DWORD bytes_written = 0;
    DWORD wret, e;
    hfile.ol.Offset = (DWORD)(block*SE3_COMM_BLOCK);
    hfile.ol.OffsetHigh = 0;
    if (!WriteFile(hfile.h, buf, (DWORD)(nblocks*SE3_COMM_BLOCK), &bytes_written, &hfile.ol))
    {
        e = GetLastError();
        if (e == ERROR_IO_PENDING) {
            wret = WaitForSingleObject(hfile.ol.hEvent, timeout);
            if (WAIT_OBJECT_0 == wret) {
                if (GetOverlappedResult(hfile.h, &hfile.ol, &bytes_written, FALSE)) {
                    if (bytes_written == nblocks*SE3_COMM_BLOCK) {
                        success = true;
                    }
                }
            }
            else if (WAIT_TIMEOUT == wret) {
                //CancelIo(hfile.h);
                //ResetEvent(hfile.ol.hEvent);
                se3_trace(("se3c_write timeout\n"));
            }
        }
    }
    else {
        success = true;
    }
    if (!success) {
        se3_trace(("se3c_write fail\n"));
    }
    return success;
}

bool se3c_read(uint8_t* buf, se3_file hfile, size_t block, size_t nblocks, uint32_t timeout)
{
    bool success = false;
    DWORD bytes_read = 0;
    DWORD wret, e;
    hfile.ol.Offset = (DWORD)(block*SE3_COMM_BLOCK);
    hfile.ol.OffsetHigh = 0;
    if (!ReadFile(hfile.h, buf, (DWORD)(nblocks*SE3_COMM_BLOCK), NULL, &hfile.ol))
    {
        e = GetLastError();
        if (e == ERROR_IO_PENDING) {
            wret = WaitForSingleObject(hfile.ol.hEvent, timeout);
            if (WAIT_OBJECT_0 == wret) {
                if (GetOverlappedResult(hfile.h, &hfile.ol, &bytes_read, FALSE)) {
                    if (bytes_read == nblocks*SE3_COMM_BLOCK) {
                        success = true;
                    }
                }
                else {
                    e = GetLastError();
                }
            }
            else if (WAIT_TIMEOUT == wret) {
                //CancelIo(hfile.h);
                //ResetEvent(hfile.ol.hEvent);
                se3_trace(("se3c_read timeout\n"));
            }
        }
    }
    else {
        success = true;
    }
    if (!success) {
        se3_trace(("se3c_read fail\n"));
    }
    return success;
}

void se3c_close(se3_file hfile) {
	if (hfile.h != INVALID_HANDLE_VALUE && hfile.h != 0) {
		CloseHandle(hfile.ol.hEvent);
		CloseHandle(hfile.h);
		hfile.h = INVALID_HANDLE_VALUE;
	}
}

#else
/* UNIX file operations */

bool se3c_unix_lock(int fd) {
    struct flock fl;
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = getpid();
    return (-1 != fcntl(fd, F_SETLK, &fl));
}
void se3c_unix_unlock(int fd) {
    struct flock fl;
    fl.l_type = F_ULOCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = getpid();
    fcntl(fd, F_SETLK, &fl);
}

void se3c_drive_init(se3_drive_it* it)
{

    it->fp_ = fopen("/proc/mounts", "r");

}

bool se3c_drive_next(se3_drive_it* it)
{
    char buf[SE3_DRIVE_BUF_MAX];
    if (it->fp_ == NULL)return false;
    if (NULL != fgets(it->buf_, SE3_DRIVE_BUF_MAX, it->fp_))
    {
        sscanf(it->buf_, "%*s%s", buf);
        strcpy(it->buf_, buf);
        it->path = it->buf_;
        return true;
    }
    fclose(it->fp_);
    it->fp_ = NULL;
    return false;
}

bool se3c_write(uint8_t* buf, se3_file hfile, size_t block, size_t nblocks, uint32_t timeout)
{
    memcpy(hfile.buf, buf, nblocks*SE3_COMM_BLOCK);
    if (nblocks*SE3_COMM_BLOCK != pwrite(hfile.fd, hfile.buf, nblocks*SE3_COMM_BLOCK, block*SE3_COMM_BLOCK)) {
        return false;
    }
    return true;
}

bool se3c_read(uint8_t* buf, se3_file hfile, size_t block, size_t nblocks, uint32_t timeout)
{
    if (nblocks*SE3_COMM_BLOCK != pread(hfile.fd, hfile.buf, nblocks*SE3_COMM_BLOCK, block*SE3_COMM_BLOCK)) {
        return false;
    }
    memcpy(buf, hfile.buf, nblocks*SE3_COMM_BLOCK);
    return true;
}
void se3c_close(se3_file hfile) {
    if (hfile.fd >= 0) {
        close(hfile.fd);
        hfile.fd = -1;
    }
    if (NULL != hfile.buf) {
        free(hfile.buf);
        hfile.buf = NULL;
    }
    //TODO unlock
}

#endif

static void se3c_make_path(se3_char* dest, se3_char* src)
{
    size_t len = 0;
    while (src[len] != (se3_char)'\0' && len < SE3_MAX_PATH - SE3_MAGIC_FILE_LEN - 1) {
        len++;
    }
    if (len == SE3_MAX_PATH - SE3_MAGIC_FILE_LEN - 1) {
        dest[0] = (se3_char)'\0';
        return;
    }
    memcpy(dest, src, len * sizeof(se3_char));
    if (dest[len - 1] != SE3_OSSEP) {
        dest[len++] = SE3_OSSEP;
    }
    memcpy(dest + len, SE3_MAGIC_FILE, SE3_MAGIC_FILE_LEN * sizeof(se3_char));
    len += SE3_MAGIC_FILE_LEN;
    dest[len] = (se3_char)'\0';
}


static bool se3c_read_info(uint8_t* buf, se3_discover_info* info) {
	uint8_t magic_inv[SE3_MAGIC_SIZE];

	// Magic number is reversed on file; Swap High with Low and store in magic_inv
	memcpy(magic_inv + SE3_MAGIC_SIZE/2, buf, SE3_MAGIC_SIZE/2);
	memcpy(magic_inv, buf + SE3_MAGIC_SIZE/2, SE3_MAGIC_SIZE/2);

	if (memcmp(magic_inv, se3_magic, SE3_MAGIC_SIZE)) {
		return(false);
	}
	if (info != NULL) {   // Copy SEcube information
		memcpy(info->serialno, buf + SE3_DISCO_OFFSET_SERIAL, SE3_SN_SIZE);   // Serial number
		memcpy(info->hello_msg, buf + SE3_DISCO_OFFSET_HELLO, SE3_HELLO_SIZE);   // Hello message
		SE3_GET16(buf, SE3_DISCO_OFFSET_STATUS, info->status);   // Device status 
	}

    return true;
}

static bool se3c_write_magic(se3_file hfile)
{
    size_t i;
    uint8_t buf[SE3_COMM_BLOCK];
    for (i = 0; i < SE3_COMM_BLOCK; i += SE3_MAGIC_SIZE)
        memcpy(buf + i, se3_magic, SE3_MAGIC_SIZE);
    for (i = 0; i < 16; i++) {
        buf[SE3_COMM_BLOCK - 1] = (uint8_t)i;
        if (!se3c_write(buf, hfile, i, 1, SE3C_MAGIC_TIMEOUT))
            return false;
    }
    return true;
}


#ifdef _WIN32
static bool se3c_magic_init(se3_char* path, uint8_t* disco_buf, se3_discover_info* info)
{
    se3_file hfile;
    se3_char mfpath[SE3_MAX_PATH];
    se3_discover_info info_;
    se3c_make_path(mfpath, path);
    // eclusive open r/w, create if not exists
    hfile.h = CreateFileW(mfpath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED,
        0);
    se3_trace(("se3c_magic_init %ls\n", mfpath));
    if (hfile.h == INVALID_HANDLE_VALUE) {
        // cannot open
        return false;
    }
    memset((void*)&(hfile.ol), 0, sizeof(OVERLAPPED));
    hfile.ol.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (!se3c_write_magic(hfile)) {
        // cannot write
        se3c_close(hfile);
        DeleteFileW(mfpath);
        return false;
    }
    if (!se3c_read(disco_buf, hfile, 15, 1, SE3C_MAGIC_TIMEOUT)) {
        // cannot read
        se3c_close(hfile);
        DeleteFileW(mfpath);
        return false;
    }

    if (!se3c_read_info(disco_buf, &info_)) {
        // not a SECube
        se3c_close(hfile);
        DeleteFileW(mfpath);
        return false;
    }

    if (info != NULL) {
        memcpy(info, &info_, sizeof(se3_discover_info));
    }

    se3c_close(hfile);
    return true;
}

static int se3c_open_existing(se3_char* path, bool rw, uint64_t deadline, se3_file* phfile)
{
    int ret = SE3C_OK;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD e;
    se3_char mfpath[SE3_MAX_PATH];
    se3c_make_path(mfpath, path);
    se3_trace(("se3c_open_existing %ls\n", mfpath));
    do
    {
        h = CreateFileW(mfpath,
            (rw) ? (GENERIC_READ | GENERIC_WRITE) : (GENERIC_READ),
            (rw) ? (FILE_SHARE_READ) : (FILE_SHARE_READ | FILE_SHARE_WRITE),
            NULL,
            OPEN_EXISTING,
            (rw) ? (FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED) : (FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED),
            NULL);
        if (h != INVALID_HANDLE_VALUE) {
            break;
        }
        e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND) {
            ret = SE3C_ERR_NOT_FOUND;
            break;
        }
        if (e != ERROR_FILE_CHECKED_OUT) {
            // if file is already open, keep trying until deadline
            return SE3C_ERR_NO_DEVICE;
        }
        se3c_sleep();
        if (se3c_clock() > deadline && h == INVALID_HANDLE_VALUE) {
            ret = SE3C_ERR_TIMEOUT;
            break;
        }
    } while (h == INVALID_HANDLE_VALUE);

    if (ret == SE3C_OK) {
        phfile->h = h;
        memset((void*)&(phfile->ol), 0, sizeof(OVERLAPPED));
        phfile->ol.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    }
    else {
        phfile->h = INVALID_HANDLE_VALUE;
    }
    return ret;
}
#else
/* UNIX */
static bool se3c_magic_init(se3_char* path, uint8_t* disco_buf, se3_discover_info* info)
{
    se3_file hfile;
    se3_char mfpath[SE3_MAX_PATH];
    se3_discover_info info_;
    se3c_make_path(mfpath, path);
    // eclusive open r/w, create if not exists
    // TODO use fcntl lock

    hfile.locked = false;
    hfile.fd = open((char*)mfpath, O_SYNC | O_RDWR | O_CREAT | O_DIRECT | O_TRUNC, S_IWUSR | S_IRUSR);

    se3_trace(("se3c_magic_init %s\n", mfpath));
    if (hfile.fd < 0) {
        // cannot open
        return false;
    }

    hfile.buf = memalign(SE3_COMM_BLOCK, SE3_COMM_BLOCK);
    if (NULL == hfile.buf) {
        // memalign failed
        close(hfile.fd);
        unlink(mfpath);
        return false;
    }

    if (!se3c_unix_lock(hfile.fd)) {
        // cannot lock
        close(hfile.fd);
        return false;
    }

    hfile.locked = true;

    if (!se3c_write_magic(hfile)) {
        // cannot write
        se3c_close(hfile);
        unlink(mfpath);
        return false;
    }
    if (!se3c_read(disco_buf, hfile, 15, 1, SE3C_MAGIC_TIMEOUT)) {
        // cannot read
        se3c_close(hfile);
        unlink(mfpath);
        return false;
    }

    if (!se3c_read_info(disco_buf, &info_)) {
        // not a SECube
        se3c_close(hfile);
        unlink(mfpath);
        return false;
    }

    if (info != NULL) {
        memcpy(info, &info_, sizeof(se3_discover_info));
    }

    se3c_close(hfile);
    return true;
}

static int se3c_open_existing(se3_char* path, bool rw, uint64_t deadline, se3_file* phfile)
{
    int ret = SE3C_OK;
    bool lock_success = false;
    int fd = -1;
    se3_char mfpath[SE3_MAX_PATH];
    se3c_make_path(mfpath, path);
    se3_trace(("se3c_open_existing %s\n", mfpath));
    phfile->locked = false;
    if (rw) {
        fd = open(mfpath, O_SYNC | O_RDWR | O_DIRECT, S_IWUSR | S_IRUSR);
    }
    else {
        fd = open(mfpath, O_SYNC | O_RDONLY | O_DIRECT, S_IWUSR | S_IRUSR);
    }
    if (fd<0) {
        if (errno == ENOENT) {
            return SE3C_ERR_NOT_FOUND;
        }
        else {
            return SE3C_ERR_NO_DEVICE;
        }
    }

    if (rw) {
        do
        {
            lock_success = se3c_unix_lock(fd);
            if (lock_success) {
                ret = SE3C_OK;
                break;
            }
            else {
                printf("lock fail %s\n", mfpath);
            }

            se3c_sleep();
            if (se3c_clock() > deadline) {
                ret = SE3C_ERR_TIMEOUT;
                break;
            }
        } while (!lock_success);
    }


    if (ret == SE3C_OK) {
        phfile->buf = memalign(SE3_COMM_BLOCK, SE3_COMM_BLOCK * 16);
        if (NULL == phfile->buf) {
            se3c_unix_unlock(fd);
            close(fd);
            ret = SE3C_ERR_TIMEOUT;
        }
        else {
            phfile->fd = fd;
            if (rw)phfile->locked = true;
        }
    }
    return ret;
}
#endif


bool se3c_info(se3_char* path, uint64_t deadline, se3_discover_info* info)
{
    uint8_t buf[SE3_COMM_BLOCK];
    se3_file hfile;
    int r;

    r = se3c_open_existing(path, false, deadline, &hfile);
    if (r == SE3C_OK) {
        if (!se3c_read(buf, hfile, 15, 1, SE3C_MAGIC_TIMEOUT)) {
            se3c_close(hfile);
            return false;
        }
        if (!se3c_read_info(buf, info)) {
            // write again
            se3c_close(hfile);
            r = SE3C_ERR_NOT_FOUND;
        }
        else {
            se3c_close(hfile);
            return true;
        }
    }
    if (r == SE3C_ERR_NOT_FOUND) {
        if (se3c_magic_init(path, buf, info)) {
            return true;
        }
        else {
            return false;
        }
    }
    else {
        return false;
    }
    return false;
}


uint64_t se3c_deadline(uint32_t timeout) {
    return (se3c_clock() + timeout);
}


bool se3c_open(se3_char* path, uint64_t deadline, se3_file* phfile, se3_discover_info* disco) {
    uint8_t buf[SE3_COMM_BLOCK];
    se3_file hfile;
    int r;
    bool discover_info_read = false;

    r = se3c_open_existing(path, true, deadline, &hfile);
    if (r == SE3C_ERR_NOT_FOUND) {
        se3c_magic_init(path, buf, disco);
        discover_info_read = true;
        // try again regardless of result. another process may have created the magic file
        r = se3c_open_existing(path, true, deadline, &hfile);
    }

    if (r != SE3C_OK) {
        return false;
    }

    if (!discover_info_read) {
		if (!se3c_read(buf, hfile, 15, 1, SE3C_MAGIC_TIMEOUT)) {
            se3c_close(hfile);
            return false;
        }
        if (!se3c_read_info(buf, disco)) {
            // not a SECube
            se3c_close(hfile);
            return false;
        }
    }

    *phfile = hfile;
    return true;
}

#ifdef _WIN32
void se3c_pathcopy(se3_char* dest, se3_char* src)
{
    wcscpy(dest, src);
}

uint64_t se3c_clock()
{
    uint64_t ms = (uint64_t)clock();
    ms = (ms * 1000) / CLOCKS_PER_SEC;
    return ms;
}
#else
void se3c_pathcopy(se3_char* dest, se3_char* src)
{
    strcpy(dest, src);
}

uint64_t se3c_clock()
{
    uint64_t ms;
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    ms = spec.tv_sec;
    ms *= 1000;
    ms += (uint64_t)spec.tv_nsec / ((uint64_t)1000000);
    return ms;
}


#endif

