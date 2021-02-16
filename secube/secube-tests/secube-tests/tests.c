#include "tests.h"


static uint8_t test_key[32] = {
	0x99, 0x5, 0xae, 0xc3, 0x98, 0xd6, 0x26, 0x35, 0xcd, 0xf7, 0x28, 0xf6, 0xd8, 0xd3, 0x9, 0xe8,
	0xee, 0xa, 0x59, 0xce, 0x6, 0xb6, 0x39, 0x6a, 0x10, 0x8f, 0x47, 0xbc, 0xfe, 0x4f, 0xb2, 0x8d
};


void stopwatch_start(stopwatch* sw)
{
	QueryPerformanceFrequency(&(sw->frequency));
	QueryPerformanceCounter(&(sw->start));	
}

void stopwatch_stop(stopwatch* sw)
{
	QueryPerformanceCounter(&(sw->end));
}

double stopwatch_gettime(stopwatch* sw)
{
	return (double)(sw->end.QuadPart - sw->start.QuadPart) / sw->frequency.QuadPart;
}

double test_getspeed(stopwatch* sw, size_t size)
{
	double t = stopwatch_gettime(sw);
	return (size / 1024) / t;
}

void test_randbuf(size_t len, void** buf)
{
	*buf = malloc(len);
	se3c_rand(len, *buf);
}



void test_printv(size_t len, uint8_t* v)
{
	size_t i;
	for (i = 0; i < len; i++) {
		printf("%u", (unsigned)v[i]);
		if (i != len - 1) {
			printf(" ");
		}
	}
}


void test_printspeed(stopwatch* sw, size_t size)
{
	printf("%.3f", test_getspeed(sw, size));
}


