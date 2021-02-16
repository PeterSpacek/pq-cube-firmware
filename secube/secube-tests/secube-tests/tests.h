#pragma once

#ifdef _WIN32
#include <Windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "L1.h"

typedef struct {
	LARGE_INTEGER frequency;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
} stopwatch;

void stopwatch_start(stopwatch* sw);
void stopwatch_stop(stopwatch* sw);
double stopwatch_gettime(stopwatch* sw);
double test_getspeed(stopwatch* sw, size_t size);

void test_randbuf(size_t len, void** buf);

void test_printv(size_t len, uint8_t* v);
void test_printspeed(stopwatch* sw, size_t size);

bool test_echo(se3_device* dev);
bool test_Aes(se3_session* s);
bool test_AesHmacSha256s(se3_session* s);
bool test_HmacSha256(se3_session* s);
bool test_Sha256(se3_session* s);

#define NRUN (10)
