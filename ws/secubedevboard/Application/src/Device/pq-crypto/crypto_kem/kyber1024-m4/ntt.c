#include "kyber_params.h"
#include "kyber_params.h"
#include "ntt.h"
#include <stdint.h>

/* Code to generate zetas and zetas_inv used in the number-theoretic transform:

#define KYBER_ROOT_OF_UNITY 17

static const uint16_t tree[128] = {
  0, 64, 32, 96, 16, 80, 48, 112, 8, 72, 40, 104, 24, 88, 56, 120,
  4, 68, 36, 100, 20, 84, 52, 116, 12, 76, 44, 108, 28, 92, 60, 124,
  2, 66, 34, 98, 18, 82, 50, 114, 10, 74, 42, 106, 26, 90, 58, 122,
  6, 70, 38, 102, 22, 86, 54, 118, 14, 78, 46, 110, 30, 94, 62, 126,
  1, 65, 33, 97, 17, 81, 49, 113, 9, 73, 41, 105, 25, 89, 57, 121,
  5, 69, 37, 101, 21, 85, 53, 117, 13, 77, 45, 109, 29, 93, 61, 125,
  3, 67, 35, 99, 19, 83, 51, 115, 11, 75, 43, 107, 27, 91, 59, 123,
  7, 71, 39, 103, 23, 87, 55, 119, 15, 79, 47, 111, 31, 95, 63, 127};


static int16_t fqmul(int16_t a, int16_t b) {
  return montgomery_reduce((int32_t)a*b);
}

void init_ntt() {
  unsigned int i, j, k;
  int16_t tmp[128];

  tmp[0] = MONT;
  for(i = 1; i < 128; ++i)
    tmp[i] = fqmul(tmp[i-1], KYBER_ROOT_OF_UNITY*MONT % KYBER_Q);

  for(i = 0; i < 128; ++i)
    zetas[i] = tmp[tree[i]];

  k = 0;
  for(i = 64; i >= 1; i >>= 1)
    for(j = i; j < 2*i; ++j)
      zetas_inv[k++] = -tmp[128 - tree[j]];

  zetas_inv[127] = MONT * (MONT * (KYBER_Q - 1) * ((KYBER_Q - 1)/128) % KYBER_Q) % KYBER_Q;
}

*/

const int16_t zetas[64] = { 2226, 430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869,
1574, 1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
3221, 3021, 996, 991, 958, 1869, 1522, 1628 };

const int16_t zetas_asm[128] = {
// 7 & 6 & 5 layers
2571, 2970, 1812, 1493, 1422, 287, 202,
// 1st loop of 4 & 3 & 2 layers
3158, 573, 2004, 1223, 652, 2777, 1015,
// 2nd loop of 4 & 3 & 2 layers
622, 264, 383, 2036, 1491, 3047, 1785,
// 3rd loop of 4 & 3 & 2 layers
1577, 2500, 1458, 516, 3321, 3009, 2663,
// 4th loop of 4 & 3 & 2 layers
182, 1727, 3199, 1711, 2167, 126, 1469,
// 5th loop of 4 & 3 & 2 layers
962, 2648, 1017, 2476, 3239, 3058, 830,
// 6th loop of 4 & 3 & 2 layers
2127, 732, 608, 107, 1908, 3082, 2378,
// 7th loop of 4 & 3 & 2 layers
1855, 1787, 411, 2931, 961, 1821, 2604,
// 8th loop of 4 & 3 & 2 layers
1468, 3124, 1758, 448, 2264, 677, 2054,
// 1 layer
2226, 430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
};

const int16_t zetas_inv_asm[128] = {
// 1 layer
1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535, 1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685, 1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
// 1st loop of 2 & 3 & 4 layers
1275, 2652, 1065, 2881, 1571, 205, 1861,
// 2nd loop of 2 & 3 & 4 layers
725, 1508, 2368, 398, 2918, 1542, 1474,
// 3rd loop of 2 & 3 & 4 layers
951, 247, 1421, 3222, 2721, 2597, 1202,
// 4th loop of 2 & 3 & 4 layers
2499, 271, 90, 853, 2312, 681, 2367,
// 5th loop of 2 & 3 & 4 layers
1860, 3203, 1162, 1618, 130, 1602, 3147,
// 6th loop of 2 & 3 & 4 layers
666, 320, 8, 2813, 1871, 829, 1752,
// 7th loop of 2 & 3 & 4 layers
1544, 282, 1838, 1293, 2946, 3065, 2707,
// 8th loop of 2 & 3 & 4 layers
2314, 552, 2677, 2106, 1325, 2756, 171,
// 5 & 6 & 7 layers
3127, 3042, 1907, 1836, 1517, 359, 1932,
// 128^-1 * 2^32
1441
};

extern void ntt_fast(int16_t *, const int16_t *);
/*************************************************
* Name:        ntt
*
* Description: Inplace number-theoretic transform (NTT) in Rq
*              input is in standard order, output is in bitreversed order
*
* Arguments:   - int16_t *poly: pointer to input/output vector of 256 elements of Zq
**************************************************/
void ntt(int16_t *poly) {
    ntt_fast(poly, zetas_asm);
}

extern void invntt_fast(int16_t *, const int16_t *);
/*************************************************
* Name:        invntt
*
* Description: Inplace inverse number-theoretic transform in Rq
*              input is in bitreversed order, output is in standard order
*
* Arguments:   - int16_t *poly: pointer to input/output vector of 256 elements of Zq
**************************************************/
void invntt(int16_t *poly) {
    invntt_fast(poly, zetas_inv_asm);
}
