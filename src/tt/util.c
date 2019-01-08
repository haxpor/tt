#include "util.h"
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "common_debug.h"

// string used in randomize operation
static const char* ALPHAN_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// pre-calculated to cache the length of alphanumeric string (for better performance later)
static const int ALPHAN_STR_LEN = 62;

/// random integer from 0 to max (exclusion)
static int randomi_(int max);

int randomi_(int max)
{
	return rand() % max;
}

void tt_util_init()
{
	// set seed in random function
	srand(time(NULL));
}

void tt_util_generate_nonce(char* dst, int length)
{
	assert(dst != NULL && "destination string should not be NULL");
	assert(length > 0 && "result string length should be more than 0");

	for (int i=0; i<length; i++)
	{
		dst[i] = ALPHAN_STR[randomi_(ALPHAN_STR_LEN)];
	}
}
