#include "tt_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <curl/curl.h>
#include "tt_util.h"
#include "tt_types.h"
#include "mjson.h"

#define NONCE_LENGTH 42
#define AUTHORIZATION_HEADER_BUFF_LEN 1024
#define URL_BUFF_LEN 1024

enum api_request_type
{
  API_REQUEST_TYPE_POST_TWEET,
  API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE
};

struct api_response_st_
{
  enum api_request_type request_type;
  int error_code;
  char error_message[255];
};

///
/// Initialize defaults value for res_st
///
/// \param res_st api response structure. See api_response_st_.
///
static void init_defaults_api_response_st_(struct api_response_st_* res_st);

///
/// worker function to actually make HTTP request
/// api result will be written into res_st.
///
/// \param http_method http method. See enum e_http_method
/// \param base_url base url of api to make request to
/// \param res_st api response structure. See api_response_st_.
/// \param param additional parameter list, end the list with NULL.
/// 
static void do_http_request(enum e_http_method http_method, const char* base_url, enum api_request_type req_type, struct api_response_st_* res_st, const KEYVALUE* param, ...);

static size_t receive_response(void* contents, size_t size, size_t nmemb, void* userp);

void init_defaults_api_response_st_(struct api_response_st_* res_st)
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

void do_http_request(enum e_http_method http_method, const char* base_url, enum api_request_type req_type, struct api_response_st_* res_st, const KEYVALUE* param, ...)
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

  // form the variable list of input additional parameters list
  va_list param_va;
  va_start(param_va, param);

  // we also want to get sorted kv result back from signature generation
  KEYVALUE* sorted_kv = NULL;
  int sorted_kv_size = 0;
  // get signature base string
  char* signature_base_str = tt_util_generate_signature(HTTP_METHOD_POST,
    base_url,
    consumer_key,
    nonce,
    "HMAC-SHA1",
    timestamp,
    access_token,
    "1.0",
    &sorted_kv,
    &sorted_kv_size,
    param,  // we also need to send in the first parameter
    param_va);

  // end variable list
  va_end(param_va);

  // get signing key
  const char* consumer_secret = tt_util_getenv_value(tt_env_name_CONSUMER_SECRET);
  const char* oauth_secret = tt_util_getenv_value(tt_env_name_ACCESS_TOKEN_SECRET);

  char* signingkey = tt_util_get_signingkey(consumer_secret, oauth_secret);

  // apply with hmac-sha1 algorithm
  unsigned char* signature_digest = tt_util_hmac_sha1(signature_base_str, signingkey);

  // compute base64
  // size is fixed, it's 20 bytes result from hmac-sha1
  char* signature = tt_util_base64(signature_digest, 20);

  // percent encode signature
  char* pen_signature = tt_util_percent_encode(signature);

  // form the Authorization header as part of HTTP request
  char authoriz_header[AUTHORIZATION_HEADER_BUFF_LEN+1];
  memset(authoriz_header, 0, sizeof(authoriz_header));
  snprintf(authoriz_header, sizeof(authoriz_header) - 1, "Authorization: OAuth oauth_consumer_key=\"%s\", oauth_nonce=\"%s\", oauth_signature=\"%s\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"%ld\", oauth_token=\"%s\", oauth_version=\"1.0\"", consumer_key, nonce, pen_signature, timestamp, access_token);

  // free returned string
  free(signature_base_str);
  free(signingkey);
  free(signature);
  free(pen_signature);

  // make request with curl
  struct curl_slist *chunk = NULL;
  chunk = curl_slist_append(chunk, authoriz_header);
  CURLcode res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

  if (req_type == API_REQUEST_TYPE_POST_TWEET)
  {
    // percent encode status
    // find key "status" and get its value
    const char* val = NULL;

    for (int i=0; i<sorted_kv_size; i++)
    {
      if (strcmp(sorted_kv[i].key, "status") == 0)
      {
        val = sorted_kv[i].value;
        break;
      }
    }

    char* pen_status = tt_util_percent_encode(val);

    char url_buff[URL_BUFF_LEN+1];
    memset(url_buff, 0, sizeof(url_buff));
    snprintf(url_buff, URL_BUFF_LEN, "%s?status=%s", base_url, pen_status);

    free(pen_status);

    curl_easy_setopt(curl, CURLOPT_URL, url_buff);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "tt cli");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)res_st);
  }
  else if (req_type == API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE)
  {
    // will save string from sorted array then fill in these variables
    const char* command_ptr = NULL;
    const char* total_bytes_ptr = NULL;
    const char* media_type_ptr = NULL;

    bool command_cmp_checked = false;
    bool total_bytes_cmp_checked = false;
    bool media_type_cmp_checked = false;

    for (int i=0; i<sorted_kv_size; i++)
    {
      if (!command_cmp_checked && strcmp(sorted_kv[i].key, "command") == 0)
      {
        command_ptr = sorted_kv[i].value;
        command_cmp_checked = true;
      }
      else if (!total_bytes_cmp_checked && strcmp(sorted_kv[i].key, "total_bytes") == 0)
      {
        total_bytes_ptr = sorted_kv[i].value;
        total_bytes_cmp_checked = true;
      }
      else if (!media_type_cmp_checked && strcmp(sorted_kv[i].key, "media_type") == 0)
      {
        media_type_ptr = sorted_kv[i].value;
        media_type_cmp_checked = true;
      }
    }

    // the only value we neee to pay attention to is media_type
    // we need to percent encode it
    char* pen_media_type = tt_util_percent_encode(media_type_ptr);

    char url_buff[URL_BUFF_LEN+1];
    memset(url_buff, 0, sizeof(url_buff));
    snprintf(url_buff, sizeof(url_buff), "%s?command=%s&total_bytes=%s&media_type=%s", base_url, command_ptr, total_bytes_ptr, pen_media_type);

    free(pen_media_type);

    printf("url = %s\n", url_buff);

    curl_easy_setopt(curl, CURLOPT_URL, url_buff);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "tt cli");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)res_st);
  }
  else
  {
    fprintf(stderr, "Unknown request type to Twitter API");
    goto CLEANUP;
  }

  res = curl_easy_perform(curl);
  // check for errors
  if (res != CURLE_OK)
  {
    fprintf(stderr, "Curl failed: %s\n", curl_easy_strerror(res));
  }

CLEANUP:

  for (int i=0; i<sorted_kv_size; i++)
  {
    // free sorted parameters
    // free key & value attribute, and KEYVALUE struct
    // we won't be revisit this item again, so it's safe to free it now
    free(sorted_kv[i].key);
    sorted_kv[i].key = NULL;
    free(sorted_kv[i].value);
    sorted_kv[i].value = NULL;
  }

  // free the whole sorted params
  free(sorted_kv);
  sorted_kv = NULL;

  // clean up
  curl_easy_cleanup(curl);
  curl_slist_free_all(chunk);
}

void tt_api_update_status(const char* status, int* error_code)
{
  struct api_response_st_ res_st;
  init_defaults_api_response_st_(&res_st);
  res_st.request_type = API_REQUEST_TYPE_POST_TWEET;

  do_http_request(HTTP_METHOD_POST, "https://api.twitter.com/1.1/statuses/update.json", API_REQUEST_TYPE_POST_TWEET, &res_st, &(KEYVALUE){"status", (char*)status}, NULL);

  // if success, then 
  if (res_st.error_code == 0)
  {
    printf("Tweeted done\n");
  }
}

void tt_api_update_status_with_image(const char* status, const char* image_path, int* error_code)
{
  struct api_response_st_ res_st;
  init_defaults_api_response_st_(&res_st);
  res_st.request_type = API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE;
  
  // determine the size of the input file
  long image_file_size = tt_util_get_filesize(image_path);
  if (image_file_size == -1)
  {
    // error occurs
    // TODO: should we also set error_code's value before returning?
    return;
  }
  // convert file size to string
  // maximum file size supported by twitter is 5MB so 5e+6 in which total character length is 7
  char file_size_s[7+1];
  memset(file_size_s, 0, sizeof(file_size_s));
  snprintf(file_size_s, sizeof(file_size_s)-1, "%ld", image_file_size);

  // determine the input file extension
  const char* file_extension = tt_util_get_fileextension(image_path);
  if (file_extension == NULL)
  {
    // TODO: should we also set error_code's value before returning?
    return;
  }
  printf("file extension = %s\n", file_extension);

  // form media type string
  char media_type_s[10+1];
  memset(media_type_s, 0, sizeof(media_type_s));
  snprintf(media_type_s, sizeof(media_type_s), "image/%s", file_extension);
  
  // send INIT command via API
  do_http_request(HTTP_METHOD_POST, "https://upload.twitter.com/1.1/media/upload.json", API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE, &res_st, &(KEYVALUE){"command", "INIT"}, &(KEYVALUE){"total_bytes", file_size_s}, &(KEYVALUE){"media_type", media_type_s}, NULL);

  // if success, then 
  if (res_st.error_code == 0)
  {
    printf("Tweeted with image(s) done\n");
  }
}
