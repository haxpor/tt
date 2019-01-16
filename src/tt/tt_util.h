#ifndef util_h_
#define util_h_

#include <time.h>
#include "tt_types.h"

///
/// Initialization of util
/// Call this for the first time using it.
extern void tt_util_init();

///
/// Get environment variable value from name
///
/// \param name environment variable name
/// \return environment variable value. No needto free it after using it.
///
extern const char* tt_util_getenv_value(enum e_env_name name);

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
/// Note: User has responsibility to free the returned string as such result string is created dyanmically.
///
/// \param http_method HTTP request method. See enum e_http_method.
/// \param request_url Request url for twitter REST api
/// \param status status to update on twitter
/// \param oauth_consumer_key OAuth consumer key
/// \param oauth_nonce OAuth nonce
/// \param timestamp Unix timestamp in seconds
/// \param oauth_token Oauth token
/// \param oauth_version Oauth version
/// \return Generated signature string
///
extern char* tt_util_generate_signature_for_updateapi(enum e_http_method http_method, const char* request_url, const char* status, const char* oauth_consumer_key, const char* oauth_nonce, const char* oauth_signature_method, time_t timestamp, const char* oauth_token, const char* oauth_version);

///
/// Do a percent encode on input string.
///
/// Note: User has responsibility to free the returned string as such result string is created dyanmically.
///
/// \param string input string
/// \return Percent encoded string.
///
extern char* tt_util_percent_encode(const char* string);

///
/// Get the signing key.
/// Note: caller has responsibility to free the returned string as it was created dynamically on heap.
///
/// \param consumer_secret consumer secret
/// \param oauth_token_secret oauth token secret
/// \return Signing key
///
extern char* tt_util_get_signingkey(const char* consumer_secret, const char* oauth_token_secret);

///
/// Compute HMAC-SHA1
/// User has no need to free string after done using it.
///
/// \param data input data to compute digest. Assume null-terminated string.
/// \param key key used in compute digest. Assume null-terminated string.
/// \return Pointer to returned string.
///
extern unsigned char* tt_util_hmac_sha1(const char* data, const char* key);

///
/// Compute base64.
/// Note: User has responsibility to free returned string after done using it.
///
/// \param buffer input buffet to get compute base64
/// \parm length size
/// \return Dynamically allocated string on the heap.
///
extern char* tt_util_base64(const unsigned char* buffer, size_t length);

#endif