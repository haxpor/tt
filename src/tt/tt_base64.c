#include "base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

#define MASKBIT1 0x00FC0000
#define MASKBIT2 0x0003F000
#define MASKBIT3 0x00000FC0
#define MASKBIT4 0x0000003F

#define BITSHIFT1 18
#define BITSHIFT2 12
#define BITSHIFT3 6

// base64 character table
char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* tt_base64(const void* input, int size)
{
  printf("input size: %d\n", size);

  // determine the desire size that can be divided by 3
  int desire_size = ceil(ceil(size * 1.0 / 3) * 3);
  // calculate the padding size
  int padding_size = desire_size - size;

  printf("desire size = %d\n", desire_size);
  printf("padding size = %d\n", padding_size);

  // allocate returned string
  const int allocated_size = ceil(4.0 / 3 * desire_size);
  printf("allocated size = %d (real buffer is %d)\n", allocated_size, allocated_size+1);
  char* result_str = malloc(sizeof(char) * (allocated_size+1));
  memset(result_str, 0, sizeof(char) * (allocated_size+1));

  // allocate padded buffer
  unsigned char buff[size + padding_size];
  // this also automatically pad our data with 0s
  memset(buff, 0, sizeof(buff));

  // copy input data to our operating buffer data
  memcpy(buff, input, size);

  // debug printing element values
  for (int i=0 ;i<sizeof(buff); i++)
  {
    printf("%X", buff[i]);
  }
  printf("\n");

  // buffer for each 3 read bytes
  unsigned int read_3bytes = 0;

  // result index
  int result_i = 0;

  // iterate through byte-by-byte from input data with step of 3 bytes a time
  for (int i=0; i<size+padding_size; i+=3)
  {
    // reconstructure the bits into read3-bytes
    read_3bytes = (buff[i] << 16) | (buff[i+1] << 8) | buff[i+2];

    // use mask-bit to get 4 ascii characters
    result_str[result_i++] = base64_table[(read_3bytes >> 18) & 0x3F];
    result_str[result_i++] = base64_table[(read_3bytes >> 12) & 0x3F];
    result_str[result_i++] = base64_table[(read_3bytes >> 6) & 0x3F];
    result_str[result_i++] = base64_table[read_3bytes & 0x3F];
    printf("%X %X %X %X\n", result_str[result_i-4], result_str[result_i-3], result_str[result_i-2], result_str[result_i-1]);
  }

  // replace padding with '='
  if (padding_size > 0)
  {
    for (int i=allocated_size-1; i > allocated_size-1-padding_size; i--)
    {
      result_str[i] = '=';
    }
  }
  
  return result_str;
}
