#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tt/util.h"

#define NONCE_LENGTH 42

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

  // get signature base string
  char* signature_str = tt_util_generate_signature_for_updateapi(HTTP_METHOD_POST,
    "https://api.twitter.com/1.1/statuses/update.json",
    "Ladies + Gentlemen",
    consumer_key,
    nonce,
    "HMAC-SHA1",
    tt_util_get_current_timestamp(),
    access_token,
    "1.0");
  printf("signature = %s\n", signature_str);

  // get signing key
  const char* consumer_secret = getenv("TT_CONSUMER_SECRET");
  const char* oauth_secret = getenv("TT_ACCESS_TOKEN_SECRET");

  char* signingkey = tt_util_get_signingkey(consumer_secret, oauth_secret);
  printf("signing key = %s\n", signingkey);

  // free returned string
  free(signature_str);
  free(signingkey);

	return 0;
}
