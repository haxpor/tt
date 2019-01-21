#ifndef api_h_
#define api_h_

#include <stdio.h>

#define tt_update_status(status, error_code) tt_api_update_status(status, error_code)
#define tt_update_status_with_images(status, error_code, image_filepaths, image_filepaths_size) tt_api_update_status_with_images(status, error_code, image_filepaths, image_filepaths_size)

///
/// Tweet update
///
/// \param status status text to update on twitter
/// \param error_code error code to receive error code back in case there's error occurred. 0 means success, otherwise means error. It can be NULL to not receive any result of operation.
///
extern void tt_api_update_status(const char* status, int* error_code);

///
/// Tweet update with images
/// Accept image path up to 4 which is the maximum limitation of number of image support on Twitter.
///
/// \param status status text to update on twitter
/// \param error_code error code to receive error code back in case there's error occurred. 0 means success, otherwise means error. It can be NULL to not receive any result of operation.
/// \param image_paths path to image file to upload along with this tweet. This can be NULL if no need to tweet with image. Assume its element is null-terminated string.
/// \param image_paths_size number of element inside image path array
///
extern void tt_api_update_status_with_images(const char* status, int* error_code, const char* image_paths[], size_t image_paths_size);

#endif
