
#include "randombytes.h"
#include "se3_rand.h"


int randombytes(uint8_t *buf, size_t n) {
	if ( n == se3_rand(n, buf)){
		return 0;
	}
	return -1;
}
