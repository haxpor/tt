#include <stdio.h>
#include "tt/util.h"

int main(int argc, char* argv[])
{
	tt_util_init();

	char buffer[4+1];
	buffer[0] = 'A';
	buffer[1] = 'B';
	buffer[2] = 'C';
	buffer[3] = 'D';

	tt_util_generate_nonce(buffer, 2);
	printf("%s\n", buffer);
	return 0;
}
