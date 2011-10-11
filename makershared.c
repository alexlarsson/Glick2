#include <sys/mount.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int
main (int argc,
      char **argv)
{
  int res;

  res = mount ("/", "/",
	       NULL, MS_SHARED|MS_REC, NULL);

  if (res != 0) {
    perror ("Failed to make rshared");
    return 1;
  }
  return 0;
}
