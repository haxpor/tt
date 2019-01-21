#ifndef tt_types_h_
#define tt_types_h_

/// method for http request
enum e_http_method
{
  HTTP_METHOD_GET,
  HTTP_METHOD_POST
};

enum e_env_name
{
  tt_env_name_CONSUMER_KEY,
  tt_env_name_ACCESS_TOKEN,
  tt_env_name_CONSUMER_SECRET,
  tt_env_name_ACCESS_TOKEN_SECRET
};

struct key_value_ptr_st
{
  char* key;
  char* value;

  // size of value, although value is char pointer but in case it's not
  // then use this size to get actual size of it
  // 
  // in case of null-terminated string, it's length of character in the string not include null-terminated character
  size_t size;
};
typedef struct key_value_ptr_st KEYVALUE;

#endif
