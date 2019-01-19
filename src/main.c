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

    // check if user enter additional paraemters but not enough argument there
    if (argc > 3 && argc < 5)
    {
      fprintf(stderr, "Missing image path!\n");
      return -1;
    }

     // receive error code back in case there is
    int error_code = 0;

    // get additional parameters for the command
    // in this case, it's image path
    if (argc >= 5)
    {
      // check for supported flags
      if (strncmp(argv[3], "-f", 2) == 0)
      {
        // get file path
        const char* file_path = argv[4];
        printf("file path = %s\n", file_path);

        // tweet to twitter with a single image
        tt_update_status_with_image(status, file_path, &error_code);
        if (error_code > 0)
        {
          return -1;
        }
      }
    }
    else
    {
      // tweet to twitter
      tt_update_status(status, &error_code);
      if (error_code > 0)
      {
        return -1;
      }
    }
  }
  
	return 0;
}
