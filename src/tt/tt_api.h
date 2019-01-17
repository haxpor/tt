#ifndef api_h_
#define api_h_

#define tt_update_status(status) tt_api_update_status(status)

///
/// Tweet update
///
/// \param status status text to update on twitter
///
extern void tt_api_update_status(const char* status);

#endif
