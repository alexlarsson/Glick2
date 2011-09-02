#define _GNU_SOURCE /* Required for CLONE_NEWNS */
#include <sys/mount.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define GLICK_PREFIX "/opt/glick"

int
main (int argc,
      char **argv)
{
  int res;
  char *path;
  char *executable_relative;
  char *executable;
  char **child_argv;
  int i, j, fd, argv_offset;

  /* The initial code is run with a high permission euid
     (at least CAP_SYS_ADMIN), so take lots of care. */

  if (argc < 3) {
    fprintf (stderr, "Not enough arguments. Need source dir and executable relative path.\n");
    return 1;
  }

  fd = 0;
  argv_offset = 1;
  path = argv[argv_offset++];
  executable_relative = argv[argv_offset++];

  if (argc >= 5 &&
      argv[argv_offset] != NULL &&
      argv[argv_offset+1] != NULL &&
      strcmp (argv[argv_offset], "-fd") == 0) {
    fd = atoi(argv[argv_offset+1]);
    if (fd != 0) {
      argv_offset += 2;
    }
  }

  res = unshare (CLONE_NEWNS);
  if (res != 0) {
    perror ("Creating new namespace failed");
    return 1;
  }

  res = mount (GLICK_PREFIX, GLICK_PREFIX,
	       NULL, MS_BIND, NULL);
  if (res != 0) {
    perror ("Bind mount failed");
    return 1;
  }

  res = mount (GLICK_PREFIX, GLICK_PREFIX,
	       NULL, MS_PRIVATE, NULL);
  if (res != 0) {
    perror ("Failed to make prefix namespace private");
    umount (GLICK_PREFIX);
    return 1;
  }
  res = mount (path, GLICK_PREFIX,
	       NULL, MS_BIND, NULL);
  if (res != 0) {
    perror ("Failed to bind the source directory");
    umount (GLICK_PREFIX);
    return 1;
  }

  /* Now we have everything we need CAP_SYS_ADMIN for, so drop setuid */
  setuid (getuid ());

  if (fd != 0) {
    char c = 'x';
    write (fd, &c, 1);
  }

  executable = NULL;
  child_argv = NULL;

  if (executable_relative[0] == '/') {
    executable = executable_relative;
  } else {
    executable = malloc (strlen (GLICK_PREFIX) + strlen (executable_relative) + 1);
    if (executable != NULL) {
      strcpy (executable, GLICK_PREFIX);
      strcat (executable, executable_relative);
    }
  }
  if (executable == NULL)
    goto oom;

  child_argv = malloc ((1 + argc - argv_offset + 1) * sizeof (char *));
  if (child_argv == NULL)
    goto oom;

  j = 0;
  child_argv[j++] = executable;
  for (i = argv_offset; i < argc; i++) {
    child_argv[j++] = argv[i];
  }
  child_argv[j++] = NULL;

  return execv (executable, child_argv);

 oom:
  if (executable)
    free (executable);

  fprintf (stderr, "Out of memory.\n");
  umount (GLICK_PREFIX);
  umount (GLICK_PREFIX);
  return 1;
}
