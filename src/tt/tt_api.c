#include "tt_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <curl/curl.h>
#include "tt_util.h"
#include "tt_types.h"
#include "mjson.h"

#define NONCE_LENGTH 42
#define AUTHORIZATION_HEADER_BUFF_LEN 1024
#define URL_BUFF_LEN 1024

struct api_response_st_
{
  int error_code;
  char error_message[255];
};

static void init_defauts_api_response_st_(struct api_response_st_* res_st);
// worker function to actually make HTTP request
// FIXME: Make this function generic and support other twitter's API
// error_code - to receive error back if any. NULL to not receive any error code back in case of error.
static void do_http_request(enum e_http_method http_method, const char* base_url, const char* status, struct api_response_st_* res_st, char* param, ...);
static size_t receive_response(void* contents, size_t size, size_t nmemb, void* userp);

void init_defauts_api_response_st_(struct api_response_st_* res_st)
{
  // 0 means success initially
  res_st->error_code = 0;
  // initially there's no error message, but check error_code first whether it > 0 or not,
  // if so then there's error occurs
  memset(res_st->error_message, 0, sizeof(res_st->error_message));
}

size_t receive_response(void* contents, size_t size, size_t nmemb, void* userp)
{
  // convert content to string
  const char* contents_str = contents;

  // check whether there's an error occurred as returned from api call or not
  const char* p;
  int len;
  enum mjson_tok ret = mjson_find(contents_str, strlen(contents_str), "$.errors", &p, &len);

  // if found means error happens
  // note: if it's not invalid then it means found
  if (ret != MJSON_TOK_INVALID)
  {
    // grab length of content
    size_t content_len = strlen(contents_str);

    // cast user's pointer to our known struct
    struct api_response_st_* res_st = (struct api_response_st_*)userp;

    // grab error code
    res_st->error_code = mjson_get_number(contents_str, content_len, "$.errors[0].code", 0);
    // grab error message
    mjson_get_string(contents_str, content_len, "$.errors[0].message", res_st->error_message, sizeof(res_st->error_message));

    fprintf(stderr, "Error! code %d : %s\n", res_st->error_code, res_st->error_message);
  }

  return size * nmemb;
}

void do_http_request(enum e_http_method http_method, const char* base_url, const char* status, struct api_response_st_* res_st, char* param, ...)
{
  CURL* curl;

  curl = curl_easy_init();
  if (curl == NULL)
  {
    fprintf(stderr, "Warning, curl_easy_init() failed");
    return;
  }

  // generate nonce
  char nonce[NONCE_LENGTH+1];
  memset(nonce, 0, sizeof(nonce));
  tt_util_generate_nonce(nonce, NONCE_LENGTH);

  // get following values via environment variable
  // get consumer key
  const char* consumer_key = tt_util_getenv_value(tt_env_name_CONSUMER_KEY);
  // get access token
  const char* access_token = tt_util_getenv_value(tt_env_name_ACCESS_TOKEN);

  // get timestamp
  time_t timestamp = tt_util_get_current_timestamp();

  // get signature base string
  char* signature_base_str = tt_util_generate_signature_for_updateapi(HTTP_METHOD_POST,
    base_url,
    status,
    consumer_key,
    nonce,
    "HMAC-SHA1",
    timestamp,
    access_token,
    "1.0");

  //printf("signature base string = %s\n", signature_base_str);

  // get signing key
  const char* consumer_secret = tt_util_getenv_value(tt_env_name_CONSUMER_SECRET);
  const char* oauth_secret = tt_util_getenv_value(tt_env_name_ACCESS_TOKEN_SECRET);

  char* signingkey = tt_util_get_signingkey(consumer_secret, oauth_secret);
  //printf("signing key = %s\n", signingkey);

  // apply with hmac-sha1 algorithm
  unsigned char* signature_digest = tt_util_hmac_sha1(signature_base_str, signingkey);
  //printf("signature = %s\n", signature_digest);
  //for (int i=0; i<20; i++)
  //{
  //  printf("%02X", signature_digest[i]);
  //}
  //printf("\n");

  // compute base64
  // size is fixed, it's 20 bytes result from hmac-sha1
  char* signature = tt_util_base64(signature_digest, 20);
  //printf("base64 = %s [length %lu]\n", signature, strlen(signature));

  //printf("\n\nparameters in use\n");
  //printf("- oauth_consumer_key = %s\n", consumer_key);
  //printf("- oauth_nonce = %s\n", nonce);
  //printf("- oauth_signature (raw) = %s\n", signature);
  //char* tt = tt_util_percent_encode(signature);
  //printf("- oauth_signature = %s\n", tt);
  //printf("- oauth_signature_method = %s\n", "HMAC-SHA1");
  //printf("- oauth_timestamp = %ld\n", timestamp);
  //printf("- oauth_tokoen = %s\n", access_token);
  //printf("- oauth_version = %s\n\n", "1.0");
  //free(tt);

  // print header string
  //char cmd_str[1024+1];
  //memset(cmd_str, 0, sizeof(cmd_str));
  //snprintf(cmd_str, sizeof(cmd_str) - 1, "Authorization: OAuth oauth_consumer_key=\"%s\", oauth_nonce=\"%s\", oauth_signature=\"%s\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"%ld\", oauth_token=\"%s\", oauth_version=\"1.0\"", consumer_key, nonce, pen_signature, timestamp, access_token);

  // percent encode signature
  char* pen_signature = tt_util_percent_encode(signature);

  // form the Authorization header as part of HTTP request
  char authoriz_header[AUTHORIZATION_HEADER_BUFF_LEN+1];
  memset(authoriz_header, 0, sizeof(authoriz_header));
  snprintf(authoriz_header, sizeof(authoriz_header) - 1, "Authorization: OAuth oauth_consumer_key=\"%s\", oauth_nonce=\"%s\", oauth_signature=\"%s\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"%ld\", oauth_token=\"%s\", oauth_version=\"1.0\"", consumer_key, nonce, pen_signature, timestamp, access_token);

  // print curl command
  //char* pen_status = tt_util_percent_encode(status);
  //printf("curl -X POST 'https://api.twitter.com/1.1/statuses/update.json?status=%s' -H '%s'\n", pen_status, cmd_str);
  //free(pen_status);

  // free returned string
  free(signature_base_str);
  free(signingkey);
  free(signature);
  free(pen_signature);

  //printf("Authorization header = %s\n", authoriz_header);

  // make request with curl
  struct curl_slist *chunk = NULL;
  chunk = curl_slist_append(chunk, authoriz_header);
  CURLcode res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
  
  // percent encode status
  char* pen_status = tt_util_percent_encode(status);

  char url_buff[URL_BUFF_LEN+1];
  memset(url_buff, 0, sizeof(url_buff));
  // TODO: Support other api by append all parameters here after url ...
  snprintf(url_buff, URL_BUFF_LEN, "%s?status=%s", base_url, pen_status);

  //printf("url = %s\n", url_buff);

  free(pen_status);

  curl_easy_setopt(curl, CURLOPT_URL, url_buff);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "tt cli");
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_response);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)res_st);

  res = curl_easy_perform(curl);
  // check for errors
  if (res != CURLE_OK)
  {
    fprintf(stderr, "Curl failed: %s\n", curl_easy_strerror(res));
  }

  // clean up
  curl_easy_cleanup(curl);
  curl_slist_free_all(chunk);
}

void tt_api_update_status(const char* status, int* error_code)
{
  struct api_response_st_ res_st;
  init_defauts_api_response_st_(&res_st);

  do_http_request(HTTP_METHOD_POST, "https://api.twitter.com/1.1/statuses/update.json", status, &res_st, NULL);

  // if success, then 
  if (res_st.error_code == 0)
  {
    printf("Tweeted done\n");
  }
}
