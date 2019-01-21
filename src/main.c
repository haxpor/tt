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
        // define array to hold all possible of image paths
        const int file_paths_size = argc-4;
        const char* file_paths[file_paths_size];

        // collect all image paths
        for (int i=0; i<argc-4; i++)
        {
          file_paths[i] = argv[4 + i];
        }

        // tweet with image(s)
        tt_update_status_with_images(status, &error_code, file_paths, file_paths_size);
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
