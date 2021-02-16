#include "L0.h"

static uint16_t L0_TX(se3_device* device, uint16_t cmd, uint16_t cmd_flags, uint16_t len, const uint8_t* data);
static uint16_t L0_RX(se3_device* device, uint16_t* resp_status, uint16_t* resp_len, uint8_t* resp_data);


#ifdef CUBESIM
#include "se3_proto.h"

bool se3c_write_sim(uint8_t* buf, se3_file hfile, size_t block, size_t nblocks, uint32_t timeout) {
    se3_proto_recv(1, buf, (uint32_t)(101 + block), (uint16_t)nblocks); return true;
}
bool se3c_read_sim(uint8_t* buf, se3_file hfile, size_t block, size_t nblocks, uint32_t timeout) {
    se3_proto_send(1, buf, (uint32_t)(101 + block), (uint16_t)nblocks); return true;
}
uint16_t L0_open_sim(se3_device* s) {
	uint8_t* buf = NULL;
    size_t i, k; se3_file foo = { 0 };
    memset(s, 0, sizeof(se3_device));
    s->request = (uint8_t*)malloc(SE3_COMM_N*SE3_COMM_BLOCK);
    s->response = (uint8_t*)malloc(SE3_COMM_N*SE3_COMM_BLOCK);
	buf = (uint8_t*)malloc(SE3_COMM_N * SE3_COMM_BLOCK);
    for (i = 0; i < 16; i++) {
        for (k = 0; k < SE3_COMM_BLOCK; k += SE3_MAGIC_SIZE)
            memcpy(buf + i*SE3_COMM_BLOCK + k, se3_magic, SE3_MAGIC_SIZE);
        buf[(i + 1)*SE3_COMM_BLOCK - 1] = (uint8_t)i;
    }
    se3c_write_sim(buf, foo, 0, 16, 0);
	free(buf);
    return SE3_OK;
}
#define se3c_write se3c_write_sim
#define se3c_read se3c_read_sim
#endif

// L0_TXRX
/** 
 *  \param resp_len in: maximum size of resp_data, out: effective size of resp_data 
 *  
 */
uint16_t L0_TXRX(se3_device* device, uint16_t req_cmd, uint16_t req_cmdflags, uint16_t req_len, const uint8_t* req_data, uint16_t* resp_status, uint16_t* resp_len, uint8_t* resp_data) {
	uint16_t error = 0;   // error value

	/* Check parameters are valid */
	if (device == NULL ||
		req_len > SE3_REQ_MAX_DATA)
	{
		return(SE3_ERR_PARAMS);
	}
	/* */

	/* Send Request */
	error = L0_TX(device, req_cmd, req_cmdflags, req_len, req_data);
    if (error != SE3_OK) {
        return(error);
    }
	/* */


	/* Receive Response */
	error = L0_RX(device, resp_status, resp_len, resp_data);
    if (error != SE3_OK) {
        return(error);
    }
	/* */


	return(SE3_OK);
}



static uint16_t L0_TX(se3_device* device, uint16_t cmd, uint16_t cmd_flags, uint16_t len, const uint8_t* data) {
	uint8_t* request = device->request;   // Buffer to be sent
	uint32_t cmd_token = 0;   // Command Token
#if SE3_CONF_CRC
	uint16_t crc;
#endif
	uint16_t nblocks = 0;   // Number of logical data blocks
	uint16_t n = 0;
	uint32_t offset_src = 0;   // Offset for source data buffer
	uint32_t offset_dst = 0;   // Offset for destination blocks buffer
    uint16_t len_data_and_headers = se3_req_len_data_and_headers(len);
    

    se3c_rand(sizeof(uint32_t), (uint8_t*)&cmd_token);

	/* Set header fields */
	SE3_SET16(request, SE3_REQ_OFFSET_CMD, cmd);
	SE3_SET16(request, SE3_REQ_OFFSET_CMDFLAGS, cmd_flags);
	SE3_SET16(request, SE3_REQ_OFFSET_LEN, len_data_and_headers);
	SE3_SET32(request, SE3_REQ_OFFSET_CMDTOKEN, cmd_token);
	memset(request + SE3_REQ_OFFSET_PADDING, 0, 4);
	
#if SE3_CONF_CRC
	// compute crc of headers and data
	crc = se3_crc16_update(SE3_REQ_OFFSET_CRC, request, 0);
	if (len > 0) {
		crc = se3_crc16_update(len, data, crc);
	}
	SE3_SET16(request, SE3_REQ_OFFSET_CRC, crc);
#endif

	/* Set data */
    n = (len < (SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER)) ? (len) : (SE3_COMM_BLOCK - SE3_REQ_SIZE_HEADER);
    memcpy(request + SE3_REQ_SIZE_HEADER, data, n);
    offset_dst = SE3_COMM_BLOCK;
    offset_src = n;
    nblocks = 1;
    while (offset_src < len) {
        cmd_token++;
        n = ((len - offset_src) < (SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER)) ? (len - offset_src) : (SE3_COMM_BLOCK - SE3_REQDATA_SIZE_HEADER);
        SE3_SET32(request + offset_dst, SE3_REQDATA_OFFSET_CMDTOKEN, cmd_token);
        memcpy(request + offset_dst + SE3_REQDATA_OFFSET_DATA, data + offset_src, n);
        offset_dst += SE3_COMM_BLOCK;
        offset_src += n;
        nblocks++;
    }
	/* */

	/* Send data */
    if (!se3c_write(request, device->f, 0, nblocks, SE3_TIMEOUT)) {
        return (SE3_ERR_COMM);
    }
	/* */

	return(SE3_OK);
}



static uint16_t L0_RX(se3_device* device, uint16_t* resp_status, uint16_t* resp_len, uint8_t* resp_data) {
	bool ready = false, success = true;
    size_t i = 0;
    uint16_t n;
	size_t nblocks = 0;
	uint16_t len_data_and_headers = 0, len = 0, u16tmp;
	uint32_t cmdtok0, u32tmp;
	uint64_t deadline = se3c_deadline(SE3_TIMEOUT);
    uint16_t offset_src, offset_dst;
#if SE3_CONF_CRC
	uint16_t crc;
#endif
	while (!ready) {
        se3c_sleep();
		if (!se3c_read(device->response, device->f, 0, 1, SE3_TIMEOUT)) {
			success = false;
			break;
		}
		SE3_GET16(device->response, 0, u16tmp);
		ready = (u16tmp == 1);
		if ((se3c_clock() > deadline) && !ready) {
			success = false;
			break;
		}
	}
    if (!success) {
        return SE3_ERR_COMM;
    }
    
	SE3_GET16(device->response, SE3_RESP_OFFSET_LEN, len_data_and_headers);
    len = se3_resp_len_data(len_data_and_headers);
    if (len > *resp_len) {
        return SE3_ERR_COMM;
    }
    
    nblocks = se3_nblocks(len_data_and_headers);

	if (nblocks > 1) {
		if (!se3c_read(device->response + 1*SE3_COMM_BLOCK, device->f, 1, nblocks - 1, SE3_TIMEOUT))
			return SE3_ERR_COMM;
	}

	// check cmdtokens
	SE3_GET32(device->response, SE3_RESP_OFFSET_CMDTOKEN, cmdtok0);
	for (i = 1; i < nblocks; i++) {
		cmdtok0++;
		SE3_GET32(device->response + i*SE3_COMM_BLOCK, SE3_RESPDATA_OFFSET_CMDTOKEN, u32tmp);
		if (cmdtok0 != u32tmp) {
			return SE3_ERR_COMM;
		}
	}
#if SE3_CONF_CRC
	crc = se3_crc16_update(SE3_REQ_OFFSET_CRC, device->response, 0);
#endif
	n = (len < (SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER)) ? (len) : (SE3_COMM_BLOCK - SE3_RESP_SIZE_HEADER);
	if (resp_data != NULL) {
		memcpy(resp_data, device->response + SE3_RESP_SIZE_HEADER, n);
	}
#if SE3_CONF_CRC
	if (n > 0) {
		crc = se3_crc16_update(n, device->response + SE3_RESP_SIZE_HEADER, crc);
	}
#endif
	offset_src = SE3_COMM_BLOCK;
    offset_dst = n;
    while(offset_dst < len) {
        n = ((len - offset_dst) < (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER)) ? (len - offset_dst) : (SE3_COMM_BLOCK - SE3_RESPDATA_SIZE_HEADER);
		if (resp_data != NULL) {
			memcpy(resp_data + offset_dst, device->response + offset_src + SE3_RESPDATA_SIZE_HEADER, n);
		}
#if SE3_CONF_CRC
		crc = se3_crc16_update(n, device->response + offset_src + SE3_RESPDATA_SIZE_HEADER, crc);
#endif
		offset_src += SE3_COMM_BLOCK;
        offset_dst += n;
    }

    // read headers
    SE3_GET16(device->response, SE3_RESP_OFFSET_STATUS, u16tmp);
    *resp_status = u16tmp;
    SE3_GET16(device->response, SE3_RESP_OFFSET_LEN, u16tmp);
    *resp_len = len;
#if SE3_CONF_CRC
	SE3_GET16(device->response, SE3_RESP_OFFSET_CRC, u16tmp);
	if (u16tmp != crc) {
		return SE3_ERR_COMM;
	}
#endif

	return SE3_OK;
}



uint16_t L0_echo(se3_device* device, const uint8_t* data_in, uint16_t data_in_len, uint8_t* data_out) {
    uint16_t resp_status = 0, resp_len = 0;
	uint16_t error = 0;
    
    resp_len = data_in_len;
	error = L0_TXRX(device, SE3_CMD0_ECHO, 0, data_in_len, data_in, &resp_status, &resp_len, data_out);
	if (error != SE3_OK) return(error);

	return(resp_status);
}



uint16_t L0_factoryinit(se3_device* device, const uint8_t* serialno) {
    uint16_t resp_status = 0, resp_len = 0;
	uint16_t error = 0;

    error = L0_TXRX(device, SE3_CMD0_FACTORY_INIT, 0, SE3_SERIAL_SIZE, serialno, &resp_status, &resp_len, NULL);
	if (error != SE3_OK) return(error);

	return(resp_status);
}



void L0_discover_init(se3_disco_it* it) {
	se3c_drive_init(&(it->_drive_it));
}



bool L0_discover_next(se3_disco_it* it) {
	se3_discover_info discov_nfo;
	uint64_t deadline;

	while (se3c_drive_next(&(it->_drive_it))) {
		deadline = se3c_deadline(0);
		if (se3c_info(it->_drive_it.path, deadline, &discov_nfo)) {   // True = SEcube

			memcpy(it->device_info.serialno, discov_nfo.serialno, SE3_SN_SIZE);
            memcpy(it->device_info.hello_msg, discov_nfo.hello_msg, SE3_HELLO_SIZE);
            se3c_pathcopy(it->device_info.path, it->_drive_it.path);
			it->device_info.status = discov_nfo.status;

			return true;
		}
	}
	return false;
}


bool L0_discover_serialno(uint8_t* serialno, se3_device_info* device) {
	se3_disco_it it;
	
	L0_discover_init(&it);
	while (L0_discover_next(&it)) {
		if (memcmp(serialno, it.device_info.serialno, SE3_SN_SIZE)) {
            memcpy(device, &(it.device_info), sizeof(se3_device_info));
			return(true);
		}
	}
	return(false);
}


uint16_t L0_open(se3_device* dev, se3_device_info* dev_info, uint32_t timeout)
{
	se3_file hfile;
	se3_discover_info discov_nfo;

    memset(dev, 0, sizeof(se3_device));
    memcpy(&(dev->info), dev_info, sizeof(se3_device_info));

    dev->opened = false;
	if (!se3c_open(dev->info.path, timeout, &hfile, &discov_nfo)) {
		return SE3_ERR_COMM;
	}
	if (memcmp(discov_nfo.serialno, dev->info.serialno, SE3_SN_SIZE)) {   // SEcube serial number does not match.
		se3c_close(hfile);
		return SE3_ERR_COMM;
	}
    dev->f = hfile;
    dev->request = (uint8_t*)malloc(SE3_COMM_N*SE3_COMM_BLOCK);
    dev->response = (uint8_t*)malloc(SE3_COMM_N*SE3_COMM_BLOCK);
    dev->opened = true;
	return SE3_OK;
}


void L0_close(se3_device* dev)
{
    if (dev->opened) {
        dev->opened = false;
        if (NULL != dev->request) {
            free(dev->request);
            dev->request = NULL;
        }
        if (NULL != dev->response) {
            free(dev->response);
            dev->response = NULL;
        }
        se3c_close(dev->f);
    }
}

