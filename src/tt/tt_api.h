#ifndef api_h_
#define api_h_

#define tt_update_status(status, error_code) tt_api_update_status(status, error_code)
#define tt_update_status_with_image(status, image_path, error_code) tt_api_update_status_with_image(status, image_path, error_code)

///
/// Tweet update
///
/// \param status status text to update on twitter
/// \param error_code error code to receive error code back in case there's error occurred. 0 means success, otherwise means error. It can be NULL to not receive any result of operation.
///
extern void tt_api_update_status(const char* status, int* error_code);

///
/// Tweet update with image
///
/// \param status status text to update on twitter
/// \param image_path path to image file to upload along with this tweet. This can be NULL if no need to tweet with image.
/// \param error_code error code to receive error code back in case there's error occurred. 0 means success, otherwise means error. It can be NULL to not receive any result of operation.
///
extern void tt_api_update_status_with_image(const char* status, const char* image_path, int* error_code);

#endif
