#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tt/util.h"

#define NONCE_LENGTH 42
#define TEST_STATUS "Ladies + Gentlemen"

int main(int argc, char* argv[])
{
	tt_util_init();

  // generate nonce
  char nonce[NONCE_LENGTH];
  memset(nonce, 0, sizeof(nonce));
  tt_util_generate_nonce(nonce, NONCE_LENGTH);

  // get following values via environment variable
  // get consumer key
  const char* consumer_key = getenv("TT_CONSUMER_KEY");
  // get access token
  const char* access_token = getenv("TT_ACCESS_TOKEN");

  time_t timestamp = tt_util_get_current_timestamp();

  // get signature base string
  char* signature_base_str = tt_util_generate_signature_for_updateapi(HTTP_METHOD_POST,
    "https://api.twitter.com/1.1/statuses/update.json",
    TEST_STATUS,
    consumer_key,
    nonce,
    "HMAC-SHA1",
    timestamp,
    access_token,
    "1.0");

  printf("signature base string = %s\n", signature_base_str);

  // get signing key
  const char* consumer_secret = getenv("TT_CONSUMER_SECRET");
  const char* oauth_secret = getenv("TT_ACCESS_TOKEN_SECRET");

  char* signingkey = tt_util_get_signingkey(consumer_secret, oauth_secret);
  printf("signing key = %s\n", signingkey);

  // apply with hmac-sha1 algorithm
  unsigned char* signature_digest = tt_util_hmac_sha1(signature_base_str, signingkey);
  printf("signature = %s\n", signature_digest);
  for (int i=0; i<20; i++)
  {
    printf("%02X", signature_digest[i]);
  }
  printf("\n");

  // compute base64
  // size is fixed, it's 20 bytes result from hmac-sha1
  char* signature = tt_util_base64(signature_digest, 20);
  printf("base64 = %s [length %lu]\n", signature, strlen(signature));

  printf("\n\nparameters in use\n");
  printf("- oauth_consumer_key = %s\n", consumer_key);
  printf("- oauth_nonce = %s\n", nonce);
  printf("- oauth_signature (raw) = %s\n", signature);
  char* pen_signature = tt_util_percent_encode(signature);
  printf("- oauth_signature = %s\n", pen_signature);
  printf("- oauth_signature_method = %s\n", "HMAC-SHA1");
  printf("- oauth_timestamp = %ld\n", timestamp);
  printf("- oauth_tokoen = %s\n", access_token);
  printf("- oauth_version = %s\n\n", "1.0");

  // print header string
  char cmd_str[1024+1];
  memset(cmd_str, 0, sizeof(cmd_str));
  snprintf(cmd_str, sizeof(cmd_str) - 1, "Authorization: OAuth oauth_consumer_key=\"%s\", oauth_nonce=\"%s\", oauth_signature=\"%s\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"%ld\", oauth_token=\"%s\", oauth_version=\"1.0\"", consumer_key, nonce, pen_signature, timestamp, access_token);

  // print curl command
  printf("curl -X POST 'https://api.twitter.com/1.1/statuses/update.json?status=Ladies%%20%%2B%%20Gentlemen' -H '%s'\n", cmd_str);

  // free returned string
  free(signature_base_str);
  free(signingkey);
  free(signature);
  free(pen_signature);

	return 0;
}
