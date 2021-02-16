#include "tests.h"

bool test_echo(se3_device* dev)
{
	enum {
		TEST_SIZE = 1 * 1024 * 1024
	};
	bool success = false;
	size_t rep;
	uint8_t* sendbuf, *recvbuf;
	size_t n, i;
	uint16_t r = SE3_OK;
	uint8_t* sp, *rp;
	stopwatch sw;

	test_randbuf(TEST_SIZE, &sendbuf);
	recvbuf = (uint8_t*)malloc(TEST_SIZE);

	printf("ECHO ");

	for (rep = 0; rep < NRUN; rep++) {
		sp = sendbuf;
		rp = recvbuf;
		stopwatch_start(&sw);
		n = TEST_SIZE / SE3_REQ_MAX_DATA;
		for (i = 0; i < n; i++) {
			r = L0_echo(dev, sp, SE3_REQ_MAX_DATA, rp);
			if (SE3_OK != r) goto cleanup;
			sp += SE3_REQ_MAX_DATA;
			rp += SE3_REQ_MAX_DATA;
		}
		n = TEST_SIZE%SE3_REQ_MAX_DATA;
		if (n > 0) {
			L0_echo(dev, sp, (uint16_t)n, rp);
			if (SE3_OK != r) goto cleanup;
		}
		stopwatch_stop(&sw);

		if (memcmp(sendbuf, recvbuf, TEST_SIZE)) goto cleanup;
		test_printspeed(&sw, TEST_SIZE);
		printf(" ");
	}

	printf("\n");


	success = true;
cleanup:
	free(sendbuf);
	free(recvbuf);
	return success;
}