#include <stdio.h>
#include <string.h>
#include "tt.h"

int main(int argc, char* argv[])
{
  // initialize tt
	tt_init();

  // check if user enter enough command parameter
  if (argc < 2)
  {
    fprintf(stderr, "Usage: tt <command> <option>\n");
    return -1;
  }

  // read in the command
  const char* command = argv[1];
  if (strncmp(command, "update", strlen("update")) == 0)
  {
    if (argc < 3)
    {
      fprintf(stderr, "Usage tt update <tweet update text>\n");
      return -1;
    }

    // get status text
    const char* status = argv[2];

    // receive error code back in case there is
    int error_code = 0;

    // tweet to twitter
    tt_update_status(status, &error_code);
    if (error_code > 0)
    {
      fprintf(stderr, "Error updating tweet [code: %d]\n", error_code);
      return -1;
    }
  }
  
	return 0;
}
