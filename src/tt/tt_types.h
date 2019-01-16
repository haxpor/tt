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

#endif
