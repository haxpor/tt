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
  /// tweet with normal text
  API_REQUEST_TYPE_POST_TWEET,

  /// tweet with image
  /// we need to upload the media to get media id, then tweet at the end
  API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_INIT,
  API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_APPEND,
  API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_FINALIZE
};

struct api_response_st_
{
  // error code of 0 means success, -1 mean internal library error, and others for twitter api's error codes
  int error_code;
  char error_message[255];

  /// growing contents buffer to hold all response content back from API
  char* contents;
  /// size of content
  size_t contents_size;

  /// user's data as necessary for custom handling for such API call
  void* userdata;
};

/// media struct used to send buffer of media and its size
/// internally used only
struct media_st
{
  const char* data;
  size_t size;
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

///
/// check for any error from input response's content
/// if found any error, it will set error code and message accordingly back in res_st
/// this is an internal function to facilitate multiple-steps of HTTP request for a single API action
///
/// \param contents api's response content to check. Assume it's null-terminated string.
/// \param res_st api_response_st_ to set error code and error message back if any.
///
static void check_error_from_response(const char* contents, struct api_response_st_* res_st);

void init_defaults_api_response_st_(struct api_response_st_* res_st)
{
  // 0 means success initially
  res_st->error_code = 0;
  // initially there's no error message, but check error_code first whether it > 0 or not,
  // if so then there's error occurs
  memset(res_st->error_message, 0, sizeof(res_st->error_message));

  // set null initially for our content buffer
  res_st->contents = NULL;
  res_st->contents_size = 0;

  res_st->userdata = NULL;
}

size_t receive_response(void* contents, size_t size, size_t nmemb, void* userp)
{
  // contents is not zero-terminated, and not all data is sent at once here
  // so we need to keep append data into growing buffer or enough buffer space from start
  size_t realsize = size * nmemb;
  // get user's pointer to our known struct
  struct api_response_st_* res_st = (struct api_response_st_*)userp;
  // grow the memory
  char* mem_ptr = realloc(res_st->contents, res_st->contents_size + realsize + 1);
  if (mem_ptr == NULL)
  {
    fprintf(stderr, "Error growing content buffer to receive response from API\n");
    return 0;
  }
  // set new pointer after reallocated the buffer to our contents
  res_st->contents = mem_ptr;
  // append the chunk-stream at the end of the buffer
  memcpy(res_st->contents + res_st->contents_size, contents, realsize);
  // update size of the content buffer
  res_st->contents_size += realsize;
  // set null-terminated character at the end of the chunk-stream
  res_st->contents[res_st->contents_size] = 0;

  return realsize;
}

void check_error_from_response(const char* contents, struct api_response_st_* res_st)
{
  // check whether there's an error occurred as returned from api call or not
  const char* p;
  int len;
  size_t contents_len = strlen(contents);
  enum mjson_tok ret = mjson_find(contents, contents_len, "$.errors", &p, &len);

  // if found means error happens
  // note: if it's not invalid then it means found
  if (ret != MJSON_TOK_INVALID)
  {
    // grab error code
    res_st->error_code = mjson_get_number(contents, contents_len, "$.errors[0].code", 0);
    // grab error message
    mjson_get_string(contents, contents_len, "$.errors[0].message", res_st->error_message, sizeof(res_st->error_message));

    fprintf(stderr, "Error! code %d : %s\n", res_st->error_code, res_st->error_message);
  }
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
  char* pen_signature = tt_util_percent_encode(signature, strlen(signature));

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
    const char* val = NULL;   // required
    const char* media_ids = NULL; // optional

    for (int i=0; i<sorted_kv_size; i++)
    {
      if (strcmp(sorted_kv[i].key, "status") == 0)
      {
        val = sorted_kv[i].value;
      }
      else if (strcmp(sorted_kv[i].key, "media_ids") == 0)
      {
        media_ids = sorted_kv[i].value;
      }
    }

    char* pen_status = tt_util_percent_encode(val, strlen(val));

    char url_buff[URL_BUFF_LEN+1];
    memset(url_buff, 0, sizeof(url_buff));
    if (media_ids == NULL)
      snprintf(url_buff, URL_BUFF_LEN, "%s?status=%s", base_url, pen_status);
    else
      snprintf(url_buff, URL_BUFF_LEN, "%s?status=%s&media_ids=%s", base_url, pen_status, media_ids);

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
      goto CLEANUP;
    }

    // -- all of the chunk stream that we've read is there, so we can do something with it --

    
    // everything ok, then check for error
    check_error_from_response((const char*)res_st->contents, res_st);
  }
  else if (req_type == API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_INIT)
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
    char* pen_media_type = tt_util_percent_encode(media_type_ptr, strlen(media_type_ptr));

    char url_buff[URL_BUFF_LEN];
    memset(url_buff, 0, sizeof(url_buff));
    snprintf(url_buff, sizeof(url_buff), "%s?command=%s&total_bytes=%s&media_type=%s", base_url, command_ptr, total_bytes_ptr, pen_media_type);

    free(pen_media_type);

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
      goto CLEANUP;
    }

    // -- all of the chunk stream that we've read is there, so we can do something with it --
    check_error_from_response((const char*)res_st->contents, res_st);
  }
  else if (req_type == API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_APPEND)
  {
    // will save string from sorted array then fill in these variables
    const char* command_ptr = NULL;
    const char* media_id_ptr = NULL;
    const char* segment_index_ptr = NULL;

    bool command_cmp_checked = false;
    bool media_id_cmp_checked = false;
    bool segment_index_cmp_checked = false;

    for (int i=0; i<sorted_kv_size; i++)
    {
      if (!command_cmp_checked && strcmp(sorted_kv[i].key, "command") == 0)
      {
        command_ptr = sorted_kv[i].value;
        command_cmp_checked = true;
      }
      else if (!media_id_cmp_checked && strcmp(sorted_kv[i].key, "media_id") == 0)
      {
        media_id_ptr = sorted_kv[i].value;
        media_id_cmp_checked = true;
      }
      else if (!segment_index_cmp_checked && strcmp(sorted_kv[i].key, "segment_index") == 0)
      {
        segment_index_ptr = sorted_kv[i].value;
        segment_index_cmp_checked = true;
      }
    }

    // get userdata as media_st
    struct media_st* media_piggyback = (struct media_st*)res_st->userdata;

    // note: no need to add "media" parameter here as we will send it as multipart-data
    char url_buff[URL_BUFF_LEN+1];
    memset(url_buff, 0, sizeof(url_buff));
    snprintf(url_buff, sizeof(url_buff), "%s?command=%s&media_id=%s&segment_index=%s", base_url, command_ptr, media_id_ptr, segment_index_ptr);

    curl_easy_setopt(curl, CURLOPT_URL, url_buff);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "tt cli");
    // setup to send multi-part data
    curl_mime* form = NULL;
    curl_mimepart *field = NULL;

    // - create the form
    form = curl_mime_init(curl);
    // fill in the file update field
    field = curl_mime_addpart(form);
    curl_mime_name(field, "media");
    curl_mime_data(field, media_piggyback->data, media_piggyback->size);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);

    res = curl_easy_perform(curl);
    // check for errors
    if (res != CURLE_OK)
    {
      fprintf(stderr, "Curl failed: %s\n", curl_easy_strerror(res));
      curl_mime_free(form);
      goto CLEANUP;
    }
    
    // there's no content response back for this API call
    // after we send multipart-form then we check HTTP result code
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    // if it's not 2xx which is series of success code, then there's error
    if (http_code < 200 || http_code > 299)
    {
      fprintf(stderr, "APPEND failed for media_id %s\n", media_id_ptr);

      // set error code to -1 for internal library error (which is not twitter's error codes related)
      res_st->error_code = -1;
    }

    curl_mime_free(form);
  }
  else if (req_type == API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_FINALIZE)
  {
    // will save string from sorted array then fill in these variables
    const char* command_ptr = NULL;
    const char* media_id_ptr = NULL;

    bool command_cmp_checked = false;
    bool media_id_cmp_checked = false;

    for (int i=0; i<sorted_kv_size; i++)
    {
      if (!command_cmp_checked && strcmp(sorted_kv[i].key, "command") == 0)
      {
        command_ptr = sorted_kv[i].value;
        command_cmp_checked = true;
      }
      else if (!media_id_cmp_checked && strcmp(sorted_kv[i].key, "media_id") == 0)
      {
        media_id_ptr = sorted_kv[i].value;
        media_id_cmp_checked = true;
      }
    }

    // note: no need to add "media" parameter here as we will send it as multipart-data
    char url_buff[URL_BUFF_LEN+1];
    memset(url_buff, 0, sizeof(url_buff));
    snprintf(url_buff, sizeof(url_buff), "%s?command=%s&media_id=%s", base_url, command_ptr, media_id_ptr);

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
      goto CLEANUP;
    }

    // -- all of the chunk stream that we've read is there, so we can do something with it --
    check_error_from_response((const char*)res_st->contents, res_st);
  }
  else
  {
    fprintf(stderr, "Unknown request type to Twitter API");
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
  // pre-allocate the buffer just 1 byte, will grow as need to get all of the response content
  res_st.contents = malloc(1);
  memset(res_st.contents, 0, 1);

  do_http_request(HTTP_METHOD_POST, "https://api.twitter.com/1.1/statuses/update.json", API_REQUEST_TYPE_POST_TWEET, &res_st, &(KEYVALUE){"status", (char*)status, strlen(status)}, NULL);

  // if success, then 
  if (res_st.error_code == 0)
  {
    printf("Tweeted done\n");
  }
}

void tt_api_update_status_with_images(const char* status, int* error_code, const char* image_paths[], size_t image_paths_size)
{
  // define the maximum possible space for result of media_ids string
  char media_ids_s[image_paths_size * 19 + 3 + 1];
  memset(media_ids_s, 0, sizeof(media_ids_s));
  // keep track of media_ids string current size
  int media_ids_size = 0;

  for (int i=0; i<image_paths_size; i++)
  {
    struct api_response_st_ res_st;
    init_defaults_api_response_st_(&res_st);
    // pre-allocate the buffer just 1 byte, will grow as need later
    res_st.contents = malloc(1);
    memset(res_st.contents, 0, 1);

    // determine the size of the input file
    long image_file_size = tt_util_get_filesize(image_paths[i]);
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
    snprintf(file_size_s, sizeof(file_size_s), "%ld", image_file_size);

    // determine the input file extension
    const char* file_extension = tt_util_get_fileextension(image_paths[i]);
    if (file_extension == NULL)
    {
      // TODO: should we also set error_code's value before returning?
      return;
    }

    // form media type string
    char media_type_s[10+1];
    memset(media_type_s, 0, sizeof(media_type_s));
    snprintf(media_type_s, sizeof(media_type_s), "image/%s", file_extension);

    // handling in steps for tweeting with image
    // 1. INIT command via API
    do_http_request(HTTP_METHOD_POST, "https://upload.twitter.com/1.1/media/upload.json", API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_INIT, &res_st, &(KEYVALUE){"command", "INIT", strlen("INIT")}, &(KEYVALUE){"total_bytes", file_size_s, strlen(file_size_s)}, &(KEYVALUE){"media_type", media_type_s, strlen(media_type_s)}, NULL);
    // check for any error
    if (res_st.error_code != 0)
    {
      fprintf(stderr, "INIT phase error. Code %d : %s\n", res_st.error_code, res_st.error_message);
    }

    // get media_id
    char media_id[32];
    memset(media_id, 0, sizeof(media_id));  
    int ret = mjson_get_string(res_st.contents, strlen(res_st.contents), "$.media_id_string", media_id, sizeof(media_id));
    // if media_id_string field not found, it will return 0
    if (ret == 0)
    {
      fprintf(stderr, "Cannot find media_id information");
      return;
    }

    // free contents memory as used by previous request
    free(res_st.contents);
    // clear api response structure, and reuse it
    init_defaults_api_response_st_(&res_st);
    // allocate new memory buffer 
    res_st.contents = malloc(1);
    memset(res_st.contents, 0, 1);
     
    res_st.userdata = (void*)&image_file_size;

    // 2. APPEND command via API
    // read file as binary data
    unsigned char file_buffer[image_file_size];
    if (tt_util_read_fileb(image_paths[i], file_buffer, image_file_size) <= 0)
    {
      return;
    }

    // create media struct to piggy back as user data
    struct media_st media_piggyback;
    media_piggyback.data = (const char*)file_buffer;
    media_piggyback.size = image_file_size;
    // set as piggyback userdata for response struct
    res_st.userdata = (void*)&media_piggyback;

    // note: no need to send in KEYVALUE of "media" field - it's binary value content which will be sent via multipart-form
    do_http_request(HTTP_METHOD_POST, "https://upload.twitter.com/1.1/media/upload.json", API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_APPEND, &res_st, &(KEYVALUE){"command", "APPEND", strlen("APPEND")}, &(KEYVALUE){"media_id", media_id, strlen(media_id)}, &(KEYVALUE){"segment_index", "0", strlen("0")}, NULL);
    // check for any error
    if (res_st.error_code != 0)
    {
      return;
    }

    // clear response struct then reuse it
    free(res_st.contents);
    init_defaults_api_response_st_(&res_st);
    // allocate new memory buffer
    res_st.contents = malloc(1);
    memset(res_st.contents, 0, 1);

    // 3. FINALIZE command via API
    do_http_request(HTTP_METHOD_POST, "https://upload.twitter.com/1.1/media/upload.json", API_REQUEST_TYPE_POST_TWEET_WITH_IMAGE_FINALIZE, &res_st, &(KEYVALUE){"command", "FINALIZE", strlen("FINALIZE")}, &(KEYVALUE){"media_id", media_id, strlen(media_id)}, NULL);
    // check for any error
    if (res_st.error_code != 0)
    {
      return;
    }

    // things went fine, append this media_id to result media_ids string
    if (i == 0)
    {
      snprintf(media_ids_s + media_ids_size, sizeof(media_id), "%s", media_id);

      // update the size of media_ids string as we will append next string to it
      media_ids_size += strlen(media_id);
    }
    else
    {
      snprintf(media_ids_s + media_ids_size, sizeof(media_id) + 1, ",%s", media_id);

      // update the size of media_ids string as we will append next string to it
      media_ids_size += strlen(media_id) + 1;
    }
  }
  
  // create api response struct
  struct api_response_st_ res_st;
  init_defaults_api_response_st_(&res_st);
  // pre-allocate the buffer just 1 byte, will grow as need later
  res_st.contents = malloc(1);
  memset(res_st.contents, 0, 1);
  
  // Finally tweet
  do_http_request(HTTP_METHOD_POST, "https://api.twitter.com/1.1/statuses/update.json", API_REQUEST_TYPE_POST_TWEET, &res_st, &(KEYVALUE){"status", (char*)status, strlen(status)}, &(KEYVALUE){"media_ids", media_ids_s, strlen(media_ids_s)},  NULL);
  // if success, then 
  if (res_st.error_code == 0)
  {
    printf("Tweeted done\n");
  } 
}
