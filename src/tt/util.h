#ifndef util_h_
#define util_h_

#include <time.h>

/// method for http request
enum e_http_method
{
  HTTP_METHOD_GET,
  HTTP_METHOD_POST
};

///
/// Initialization of util
/// Call this for the first time using it.
extern void tt_util_init();

///
/// Generate random alphanumeric string up to input length.
///
/// \param dst Destination string that will be filled with generated random string
/// \param lenth Length of randomized string to get
///
extern void tt_util_generate_nonce(char* dst, int length);

///
/// Get current timestamp
///
/// \return Epoch time in second.
///
extern time_t tt_util_get_current_timestamp();

///
/// Generate signature
///
/// \param http_method HTTP request method. See enum e_http_method.
/// \param request_url Request url for twitter REST api
/// \param oauth_consumer_key OAuth consumer key
/// \param oauth_nonce OAuth nonce
/// \param timestamp Unix timestamp in seconds
/// \param oauth_token Oauth token
/// \param oauth_version Oauth version
/// \return Generated signature string
///
extern const char* tt_util_generate_signature(enum e_http_method http_method, const char* request_url, const char* oauth_consumer_key, const char* oauth_nonce, const char* oauth_signature_method, time_t timestamp, const char* oauth_token, const char* oauth_version);

///
/// Do a percent encode on input string.
///
/// This function is not thread-safe.
///
/// \param string input string
/// \return Percent encoded string.
///
extern const char* tt_util_percent_encode(const char* string);

#endif
