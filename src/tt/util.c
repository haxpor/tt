#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "common_debug.h"

#define BUFFER_SIZE 840

static char dst_percent_encoded_[BUFFER_SIZE+1];

// string used in randomize operation
static const char* ALPHAN_STR = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
// pre-calculated to cache the length of alphanumeric string (for better performance later)
static const int ALPHAN_STR_LEN = 62;

/// random integer from 0 to max (exclusion)
static int randomi_(int max);

// PERCENT ENCODE TABLE
static char PERCENT_ENCODE_TABLE[66] = {
  // digits
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
  0x36, 0x37, 0x38, 0x39,

  // uppercase letters
  0x41, 0x42, 0x43, 0x44, 0x45,0x46,
  0x47, 0x48, 0x49, 0x4A, 0x4B,0x4C,
  0x4D, 0x4E, 0x4F, 0x50, 0x51,0x52,
  0x53, 0x54, 0x55, 0x56, 0x57,0x58,
  0x59, 0x5A,

  // lowercase letters
  0x61, 0x62, 0x63, 0x64, 0x65,0x66,
  0x67, 0x68, 0x69, 0x6A, 0x6B,0x6C,
  0x6D, 0x6E, 0x6F, 0x70, 0x71,0x72,
  0x73, 0x74, 0x75, 0x76, 0x77,0x78,
  0x79, 0x7A,

  // reserved characters
  0x2D, 0x2E, 0x5F, 0x7E
};

int randomi_(int max)
{
	return rand() % max;
}

void tt_util_init()
{
	// set seed in random function
	srand(time(NULL));

  // clear memory space of destination percent encoded string
  memset(dst_percent_encoded_, 0, sizeof(dst_percent_encoded_));
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

const char* tt_util_generate_signature(enum e_http_method http_method, const char* request_url, const char* oauth_consumer_key, const char* oauth_nonce, const char* oauth_signature_method, time_t timestamp, const char* oauth_token, const char* oauth_version)
{
  return NULL;
}

const char* tt_util_percent_encode(const char* string)
{
  // set entire array to 0
  memset(dst_percent_encoded_, 0, sizeof(dst_percent_encoded_));

  // get the size of the table
  int table_size = sizeof(PERCENT_ENCODE_TABLE);

  int size = strlen(string);
  int dst_i = 0;

  // loop through each byte in the input string
  for (int i = 0; i < size; i++)
  {
    // get byte-value from this byte
    unsigned char byte_value = string[i];

    bool found = false;

    // loop through table to check whether it matches any inside the table
    for (int k=0; k < table_size; k++)
    {
      // if the byte value matches, then copy it destination
      if (byte_value == PERCENT_ENCODE_TABLE[k])
      {
        dst_percent_encoded_[dst_i++] = byte_value;
        found = true;

        // to break the loop
        k = table_size;
      }
    }

    // if we need to do percent encode
    if (!found)
    {
      // '%' is 0x25 in hexadecimal
      dst_percent_encoded_[dst_i++] = 0x25;       

      // get hexadecimal value of current byte value then store to dst
      // note: %X gives result in uppercase letter already
      snprintf(dst_percent_encoded_ + dst_i, 2+1, "%X", byte_value);

      // increment dst's index
      dst_i += 2;
    }
  }

  return dst_percent_encoded_;
}
