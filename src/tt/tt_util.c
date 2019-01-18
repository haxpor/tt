#include "tt_util.h"
#include "tt_common_debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
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

///
/// get total element inside input variable list
///
/// \param first_param first parameter of the variable list
/// \param va variable list
/// \return total number of elements inside input variable list
///
static int va_func_total(const KEYVALUE* first_kv, va_list va);

///
/// collect all elements inside input variable list
/// create a new array of string pointer, then return
///
/// \param first_param first parameter of the variable list
/// \param va variable list
/// \param dst destination to write result of all variable list's elements to
/// \parm max_elem_size maximum size to set to dst
///
static void va_func_collect(const KEYVALUE* first_kv, va_list va, KEYVALUE* dst[], int max_elem_size);

int va_func_total(const KEYVALUE* first_kv, va_list va)
{
  if (first_kv == NULL)
    return 0;

  const KEYVALUE* param_kv = NULL;
  int count = 1;
  while(1) {
    param_kv = va_arg(va, const KEYVALUE*);

    if (param_kv != NULL)
      count++;
    else
      break;
  }

  return count;
}

void va_func_collect(const KEYVALUE* first_param, va_list va, KEYVALUE* dst[], int max_elem_size)
{
  if (first_param == NULL)
    return;

  //printf("[0] = %s\n", first_param);
  // store first parameter at the destination
  dst[0] = (KEYVALUE*)first_param;

  const KEYVALUE* temp_kv = NULL;
  int index = 1;
  while (1)
  {
    temp_kv = va_arg(va, const KEYVALUE*);
    if (temp_kv != NULL)
    {
      //printf("[%d] = %s\n", index, temp_s);
      if (index <= max_elem_size - 1)
        dst[index] = (KEYVALUE*)temp_kv;
      index++;
    }
    else
      break;
  }
}

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
#define SET_KV(obj, k, v)             \
  do {                                \
    obj = &(KEYVALUE){ k, v};         \
    break;                            \
  } while (1);            

// FIXME: make this function generic to generate signature for any API that needs it...
char* tt_util_generate_signature(enum e_http_method http_method, const char* request_url, const char* oauth_consumer_key, const char* oauth_nonce, const char* oauth_signature_method, time_t timestamp, const char* oauth_token, const char* oauth_version, KEYVALUE** out_sorted_kv, int* out_sorted_kv_size, const KEYVALUE* first_param, va_list params)
{
  char dst_result_signature_str[BUFFER_RESULT_SIZE+1];
  // our final result string
  memset(dst_result_signature_str, 0, sizeof(char) * (BUFFER_RESULT_SIZE+1));

  // allocate space for timestamp preparing for conversion from long to string
  char temp_timestamp_str[10+1];
  memset(temp_timestamp_str, 0, sizeof(temp_timestamp_str));
  // convert timestamp to string
  snprintf(temp_timestamp_str, sizeof(temp_timestamp_str), "%ld", timestamp);

  // get  the total elements inside input variable list
  int params_count = va_func_total(first_param, params);
  // define enough array to hold all of required oauth parameters, and additional parameters
  KEYVALUE* all_params_kv_st[6 + params_count];
  memset(all_params_kv_st, 0, sizeof(all_params_kv_st));

  // collect required oauth parameters
  SET_KV(all_params_kv_st[0], "oauth_consumer_key", (char*)oauth_consumer_key)
  SET_KV(all_params_kv_st[1], "oauth_nonce", (char*)oauth_nonce)
  SET_KV(all_params_kv_st[2], "oauth_signature_method", "HMAC-SHA1")
  SET_KV(all_params_kv_st[3], "oauth_timestamp", (char*)temp_timestamp_str)
  SET_KV(all_params_kv_st[4], "oauth_token", (char*)oauth_token)
  SET_KV(all_params_kv_st[5], "oauth_version", "1.0")

  // collect all additional parameters
  if (params_count > 0)
  {
    va_func_collect(first_param, params, all_params_kv_st + 6, params_count);
  }
  
  // sort lexi
  const int total_params_count = 6 + params_count;
  const KEYVALUE** c_all_params_kv_st = (const KEYVALUE**)all_params_kv_st;
  KEYVALUE* sorted_params = tt_util_sort_lexi(c_all_params_kv_st, total_params_count);
  // if need to return result
  if (out_sorted_kv != NULL)
  {
    // now this is user's responsibility to free it and its elements
    *out_sorted_kv = sorted_params;
  }
  if (out_sorted_kv_size != NULL)
  {
    *out_sorted_kv_size = total_params_count;
  }

  // percent encode sorted key & value result, and build a result string
  int dst_index = 0;
  for (int i=0; i< total_params_count; i++)
  {
    char* pen_key_s = PEN(sorted_params[i].key);
    char* pen_value_s = PEN(sorted_params[i].value);

    // form the string to append to result string
    snprintf(dst_result_signature_str + dst_index, BUFFER_RESULT_SIZE - dst_index, "%s=%s", pen_key_s, pen_value_s);
    // proceed index
    dst_index += strlen(pen_key_s) + 1 + strlen(pen_value_s);

    // if it's not the last one then append with &
    if (i < total_params_count-1)
    {
      snprintf(dst_result_signature_str + dst_index, BUFFER_RESULT_SIZE - dst_index, "&");
      dst_index++;
    }

    // free percent encoded strings
    free(pen_key_s);
    free(pen_value_s);

    // if no need to return result, then free attributes of KEYVALUE
    if (out_sorted_kv == NULL)
    {
      // free key & value attribute, and KEYVALUE struct
      // we won't be revisit this item again, so it's safe to free it now
      free(sorted_params[i].key);
      sorted_params[i].key = NULL;
      free(sorted_params[i].value);
      sorted_params[i].value = NULL;
    }
  }
  
  // if no need to return result, then free whole sorted kv
  if (out_sorted_kv == NULL)
  {
    // free the whole sorted params
    free(sorted_params);
    sorted_params = NULL;
  }

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

const char* tt_util_getenv_value(enum e_env_name name)
{
  if (name == tt_env_name_CONSUMER_KEY)
  {
    return getenv("TT_CONSUMER_KEY");
  }
  else if (name == tt_env_name_CONSUMER_SECRET)
  {
    return getenv("TT_CONSUMER_SECRET");
  }
  else if (name == tt_env_name_ACCESS_TOKEN)
  {
    return getenv("TT_ACCESS_TOKEN");
  }
  else if (name == tt_env_name_ACCESS_TOKEN_SECRET)
  {
    return getenv("TT_ACCESS_TOKEN_SECRET");
  }

  // otherwise
  // (should not happen)
  return NULL;
}

// size of buffer string element
#define LEXI_BUFFER_SIZE 255
KEYVALUE* tt_util_sort_lexi(const KEYVALUE* data[], int size)
{
#if defined DEBUG && 0
  for (int i=0; i<size; i++)
  {
    printf("[%d] { key: %s, value: %s }\n", i, data[i]->key, data[i]->value);
  }
  printf("\n");
#endif

  // dynamically allocate new buffer string to hold sorted string result
  KEYVALUE* new_data_buffer = malloc(size * sizeof(KEYVALUE));
  memset(new_data_buffer, 0, size * sizeof(KEYVALUE));
  for (int i=0; i<size; i++)
  {
    // dynamically create struct for this index position
    new_data_buffer[i].key = malloc(LEXI_BUFFER_SIZE+1);
    new_data_buffer[i].value = malloc(LEXI_BUFFER_SIZE+1);

    // copy string to key
    strncpy(new_data_buffer[i].key, data[i]->key, LEXI_BUFFER_SIZE);
    // copy string to value
    strncpy(new_data_buffer[i].value, data[i]->value, LEXI_BUFFER_SIZE);
  }

  int n = size;
  // temp kv used to reference to existing data
  KEYVALUE temp_kv;

  do {
    int newn = 0;
    for (int i=1; i<n; i++)
    {
      // base majorly to the key
      if (strcmp(new_data_buffer[i-1].key, new_data_buffer[i].key) > 0)
      {
        // set NULL to temp struct
        temp_kv.key = NULL;
        temp_kv.value = NULL;

        // copy key from data[i] to temp
        strncpy(temp_kv.key, new_data_buffer[i].key, LEXI_BUFFER_SIZE);
        // copy value from data[i] to temp
        strncpy(temp_kv.value, new_data_buffer[i].value, LEXI_BUFFER_SIZE);
        
        // copy key & value from data[i-1] to data[i]
        strncpy(new_data_buffer[i].key, new_data_buffer[i-1].key, LEXI_BUFFER_SIZE);
        strncpy(new_data_buffer[i].value, new_data_buffer[i-1].key, LEXI_BUFFER_SIZE);

        // copy temp to data[i-1]
        strncpy(new_data_buffer[i-1].key, temp_kv.key, LEXI_BUFFER_SIZE);
        strncpy(new_data_buffer[i-1].value, temp_kv.value, LEXI_BUFFER_SIZE);

        newn = i;
      }
    }
    n = newn;
  } while (n > 1);

#if defined DEBUG && 0
  for (int i=0; i<size; i++)
  {
    printf("[%d] { key: %s, value: %s }\n", i, new_data_buffer[i].key, new_data_buffer[i].value);
  }
#endif

  return new_data_buffer;
}
