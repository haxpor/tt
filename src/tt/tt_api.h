#ifndef api_h_
#define api_h_

#define tt_update_status(status, error_code) tt_api_update_status(status, error_code)

///
/// Tweet update
///
/// \param status status text to update on twitter
/// \param error_code error code to receive error code back in case there's error occurred. 0 means success, otherwise means error. It can be NULL to not receive any result of operation.
///
extern void tt_api_update_status(const char* status, int* error_code);

#endif
