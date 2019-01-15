#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "common_debug.h"
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#define BUFFER_SIZE 840
#define BUFFER_RESULT_SIZE 4096
#define BUFFER_RESULT_SIGNINGKEY_SIZE 255

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
}

time_t tt_util_get_current_timestamp()
{
  return time(NULL);
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

#define PEN(x) tt_util_percent_encode(x)

char* tt_util_generate_signature_for_updateapi(enum e_http_method http_method, const char* request_url, const char* status, const char* oauth_consumer_key, const char* oauth_nonce, const char* oauth_signature_method, time_t timestamp, const char* oauth_token, const char* oauth_version)
{
  char dst_result_signature_str[BUFFER_RESULT_SIZE+1];
  // our final result string
  memset(dst_result_signature_str, 0, sizeof(char) * (BUFFER_RESULT_SIZE+1));

  // allocate space for timestamp preparing for conversion from long to string
  char temp_timestamp_str[10+1];
  memset(temp_timestamp_str, 0, sizeof(temp_timestamp_str));
  // convert timestamp to string
  snprintf(temp_timestamp_str, sizeof(temp_timestamp_str), "%ld", timestamp);

  // store result from percent encoded from each one
  char* oauth_consumer_key_ptr = PEN(oauth_consumer_key);
  char* oauth_nonce_ptr = PEN(oauth_nonce);
  char* oauth_signature_method_ptr = PEN(oauth_signature_method);
  char* temp_timestamp_str_ptr = PEN(temp_timestamp_str);
  char* oauth_token_ptr = PEN(oauth_token);
  char* oauth_version_ptr = PEN(oauth_version);
  char* status_ptr = PEN(status);

  snprintf(dst_result_signature_str, BUFFER_RESULT_SIZE, "oauth_consumer_key=%s&oauth_nonce=%s&oauth_signature_method=%s&oauth_timestamp=%s&oauth_token=%s&oauth_version=%s&status=%s", oauth_consumer_key_ptr, oauth_nonce_ptr, oauth_signature_method_ptr, temp_timestamp_str_ptr, oauth_token_ptr, oauth_version_ptr, status_ptr);

  // safe to free those string pointers now
  free(oauth_consumer_key_ptr);
  free(oauth_nonce_ptr);
  free(oauth_signature_method_ptr);
  free(temp_timestamp_str_ptr);
  free(oauth_token_ptr);
  free(oauth_version_ptr);
  free(status_ptr);

  // creating a signature base string
  char* result_signature_base_string = malloc(sizeof(char) * (BUFFER_RESULT_SIZE+1));
  memset(result_signature_base_string, 0, sizeof(char) * (BUFFER_RESULT_SIZE+1));

  // check http method
  char http_method_fixed[4+1];
  memset(http_method_fixed, 0, 4+1);
  if (http_method == HTTP_METHOD_GET)
  {
    strncpy(http_method_fixed, "GET", 3);
  }
  else if  (http_method == HTTP_METHOD_POST)
  {
    strncpy(http_method_fixed, "POST", 4);
  }

  // percent encode base url
  char* base_url_ptr  = PEN(request_url);
  char* pencoded_param_str_ptr = PEN(dst_result_signature_str);

  snprintf(result_signature_base_string, BUFFER_RESULT_SIZE, "%s&%s&%s", http_method_fixed, base_url_ptr, pencoded_param_str_ptr);

  free(base_url_ptr);
  free(pencoded_param_str_ptr);

  return result_signature_base_string;
}

char* tt_util_percent_encode(const char* string)
{
  // dynamically allocate string
  char* dst_percent_encoded_ = malloc(sizeof(char) * (BUFFER_SIZE+1));
  // set entire array to 0
  memset(dst_percent_encoded_, 0, sizeof(char) * (BUFFER_SIZE+1));

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

char* tt_util_get_signingkey(const char* consumer_secret, const char* oauth_token_secret)
{
  // allocate result string dynamically
  char* signingkey_str = malloc(sizeof(char) * (BUFFER_RESULT_SIGNINGKEY_SIZE+1));
  // set empty to result string
  memset(signingkey_str, 0, sizeof(char) * (BUFFER_RESULT_SIGNINGKEY_SIZE+1));

  // percent encode
  char* consumer_secret_pen_ptr = PEN(consumer_secret);
  char* oauth_token_secret_pen_ptr = PEN(oauth_token_secret);

  snprintf(signingkey_str, BUFFER_RESULT_SIGNINGKEY_SIZE, "%s&%s", consumer_secret_pen_ptr, oauth_token_secret_pen_ptr);

  // free
  free(consumer_secret_pen_ptr);
  free(oauth_token_secret_pen_ptr);

  return signingkey_str;
}

unsigned char* tt_util_hmac_sha1(const char* data, const char* key)
{
  // pointer to returned string result of digest
  unsigned char* digest;

  digest = HMAC(EVP_sha1(), key, strlen(key), (const unsigned char*)data, strlen(data), NULL, NULL);

  return digest;
}

char* tt_util_base64(const unsigned char* buffer, size_t length)
{
  BIO* bio, *b64;
  BUF_MEM *buffer_ptr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &buffer_ptr);
  BIO_set_close(bio, BIO_NOCLOSE);

  // allocate enough space of what buffer has
  char* result_str = malloc(sizeof(char) * (buffer_ptr->length+1));
  memset(result_str, 0, sizeof(char) * (buffer_ptr->length+1));
  strncpy(result_str, buffer_ptr->data, buffer_ptr->length);

  BIO_free_all(bio);

  return result_str;
}
