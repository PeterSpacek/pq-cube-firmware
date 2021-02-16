#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "tests.h"


static uint8_t pin[32] = {
	'c','i','a','o', 0,0,0,0, 0,0,0,0, 0,0,0,0,
	0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

bool L1_tests(se3_session* session);
bool L0_tests(se3_device* dev);
bool run_tests(se3_device_info* devinfo);



bool L1_tests(se3_session* session)
{
	if (!test_Sha256(session)) {
		return false;
	}
	if (!test_HmacSha256(session)) {
		return false;
	}
	if (!test_Aes(session)) {
		return false;
	}
	if (!test_AesHmacSha256s(session)) {
		return false;
	}
	return true;
}

bool L0_tests(se3_device* dev)
{
	if (!test_echo(dev)) {
		return false;
	}

	return true;
}

bool run_tests(se3_device_info* devinfo)
{
	uint16_t r;
	se3_device dev;
	se3_session session;
	bool logged_in = false;
	bool success = false;

	r = L0_open(&dev, devinfo, 1000);
	if (SE3_OK != r) return false;

	if (!L0_tests(&dev)) {
		goto cleanup;
	}

	r = L1_login(&session, &dev, pin, SE3_ACCESS_USER);
	if (SE3_OK != r) {
		goto cleanup;
	}
	logged_in = true;

	r = L1_crypto_set_time(&session, (uint32_t)time(0));
	if (SE3_OK != r) {
		goto cleanup;
	}

	if (!L1_tests(&session)) {
		goto cleanup;
	}

	success = true;
cleanup:
	if (logged_in) {
		L1_logout(&session);
	}
	L0_close(&dev);
	return success;
}


bool init_device(se3_device_info* devinfo) {
	se3_device dev;
	se3_session session;
	se3_key key;
	bool success = false;
	bool logged_in = false;

	uint8_t testdata[32] = {
		1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4,
		1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4
	};
	uint8_t pin0[32] = {
		0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
		0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
	};

	if (SE3_OK != L0_open(&dev, devinfo, 1000)) {
		return false;
	}

	if (SE3_OK != L0_factoryinit(&dev, testdata)) {
		goto cleanup;
	}

	if (SE3_OK != L1_login(&session, &dev, pin0, SE3_ACCESS_ADMIN)) {
		goto cleanup;
	}
	logged_in = true;

	if (SE3_OK != L1_set_user_PIN(&session, pin)) {
		goto cleanup;
	}

	if (SE3_OK != L1_set_admin_PIN(&session, pin)) {
		goto cleanup;
	}

	key.name_size = 6;
	memcpy(key.name, "Alaska", key.name_size);
	key.id = 600;
	key.data_size = 32;
	key.data = testdata;
	key.validity = (uint32_t)time(0) + 365 * 24 * 3600;

	if (SE3_OK != L1_key_edit(&session, SE3_KEY_OP_UPSERT, &key)) {
		goto cleanup;
	}
	

	success = true;
cleanup:
	if (logged_in) {
		L1_logout(&session);
	}
	L0_close(&dev);
	return success;
}

#define TEST_INIT 0

int main(int argc, char* argv[])
{
	char tmp[SE3_HELLO_SIZE + 1];
	bool test_init = TEST_INIT;
	se3_disco_it it;
	printf("Wait 3s...\n");
	Sleep(3000);
	L0_discover_init(&it);
	while (L0_discover_next(&it)) {
		printf("PATH %ls\n", it.device_info.path);
		printf("SN "); test_printv(SE3_SERIAL_SIZE, it.device_info.serialno); printf("\n");
		memcpy(tmp, it.device_info.hello_msg, SE3_HELLO_SIZE);
		tmp[SE3_HELLO_SIZE] = '\0';
		printf("HELLO %s\n", tmp);
		if (test_init) {
			if (!init_device(&it.device_info)) {
				printf("INIT FAIL\n");
			}
			else {
				printf("INIT SUCCESS\n");
			}
		}
		else {
			printf("Testing\n");
			if (!run_tests(&it.device_info)) {
				printf("\nFAIL\n");
			}
			else {
				printf("\nPASS\n");
			}
		}

	}

	getchar();
}




