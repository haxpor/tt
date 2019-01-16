#ifndef base64_h_
#define base64_h_

///
/// Compute base64 from the input data.
/// User has responsibility to free the returned string when done using it.
///
/// \param input pointer to input data
/// \param size size in total of bytes for input data
/// \return Dynamically allocated string for base64 result of input.
///
extern char* tt_base64(const void* input, int size);

#endif
