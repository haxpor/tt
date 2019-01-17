#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tt.h"

int main(int argc, char* argv[])
{
	tt_init();

  // tweet to twitter
  tt_update_status("Test - nothing here");

	return 0;
}
