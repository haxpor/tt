#include <stdio.h>
#include <stdlib.h>
#include "tt/util.h"

int main(int argc, char* argv[])
{
	tt_util_init();

	//tt_util_generate_nonce(buffer, 2);
  
  const char* ret = tt_util_percent_encode("Dogs, Cats & Mice");
  printf("ret = %s\n", ret);
	return 0;
}
