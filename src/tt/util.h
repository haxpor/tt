#ifndef util_h_
#define util_h_

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

#endif
