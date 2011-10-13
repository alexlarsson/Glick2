#include "config.h"

#define _GNU_SOURCE /* Required for CLONE_NEWNS */
#include <sys/mount.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

char *
strconcat (const char *s1,
	   const char *s2,
	   const char *s3)
{
  size_t len = 0;
  char *res;

  if (s1)
    len += strlen (s1);
  if (s2)
    len += strlen (s2);
  if (s3)
    len += strlen (s3);

  res = malloc (len + 1);
  if (res == NULL)
    return NULL;

  *res = 0;
  if (s1)
    strcat (res, s1);
  if (s2)
    strcat (res, s2);
  if (s3)
    strcat (res, s3);

  return res;
}

static void
update_env_var_list (const char *var, const char *item)
{
  const char *env;
  char *value;

  env = getenv (var);
  if (env == NULL || *env == 0)
    {
      setenv (var, item, 1);
    }
  else
    {
      value = strconcat (item, ":", env);
      setenv (var, value, 1);
      free (value);
    }
}

int
main (int argc,
      char **argv)
{
  int res;
  char *mount_source;
  char *executable_relative;
  char *executable;
  char *extra_mount_source;
  char **child_argv;
  int i, j, fd, argv_offset;
  int mount_count;

  /* The initial code is run with a high permission euid
     (at least CAP_SYS_ADMIN), so take lots of care. */

  if (argc < 3) {
    fprintf (stderr, "Not enough arguments. Need source dir and executable relative path.\n");
    return 1;
  }

  argv_offset = 1;
  mount_source = argv[argv_offset++];
  executable_relative = argv[argv_offset++];

  fd = 0;
  extra_mount_source = 0;

  while (argv_offset + 1 < argc)
    {
      if (strcmp (argv[argv_offset], "-fd") == 0)
	fd = atoi (argv[argv_offset+1]);
      else if (strcmp (argv[argv_offset], "-extra") == 0)
	extra_mount_source = argv[argv_offset+1];
      else
	break;

      argv_offset += 2;
    }

  res = unshare (CLONE_NEWNS);
  if (res != 0) {
    perror ("Creating new namespace failed");
    return 1;
  }

  mount_count = 0;
  res = mount (BUNDLE_PREFIX, BUNDLE_PREFIX,
	       NULL, MS_PRIVATE, NULL);
  if (res != 0 && errno == EINVAL) {
    /* Maybe if failed because there is no mount
       to be made private at that point, letsa
       add a bind mount there. */
    res = mount (BUNDLE_PREFIX, BUNDLE_PREFIX,
		 NULL, MS_BIND, NULL);
    /* And try again */
    if (res == 0)
      {
	mount_count++; /* Bind mount succeeded */
	res = mount (BUNDLE_PREFIX, BUNDLE_PREFIX,
		     NULL, MS_PRIVATE, NULL);
      }
  }

  if (res != 0) {
    perror ("Failed to make prefix namespace private");
    goto error_out;
  }

  if (extra_mount_source != NULL)
    {
      mount (extra_mount_source, extra_mount_source,
	     NULL, MS_PRIVATE, NULL);
      res = mount (extra_mount_source, extra_mount_source,
		   NULL, MS_BIND, NULL);
      if (res != 0) {
	perror ("Failed to bind the extra source directory");
	goto error_out;
      }
      mount_count++; /* Extra mount succeeded */
    }

  res = mount (mount_source, BUNDLE_PREFIX,
	       NULL, MS_BIND, NULL);
  if (res != 0) {
    perror ("Failed to bind the source directory");
    goto error_out;
  }
  mount_count++; /* Normal mount succeeded */

  /* Now we have everything we need CAP_SYS_ADMIN for, so drop setuid */
  setuid (getuid ());

  if (fd != 0)
    {
      char c = 'x';
      write (fd, &c, 1);
    }

  executable = NULL;
  child_argv = NULL;

  if (executable_relative[0] == '/')
    executable = executable_relative;
  else
    {
      executable = malloc (strlen (BUNDLE_PREFIX) + strlen (executable_relative) + 1);
      if (executable != NULL)
	{
	  strcpy (executable, BUNDLE_PREFIX);
	  strcat (executable, executable_relative);
	}
    }

  if (executable == NULL)
    goto oom;

  child_argv = malloc ((1 + argc - argv_offset + 1) * sizeof (char *));
  if (child_argv == NULL)
    goto oom;

  j = 0;
  for (i = argv_offset; i < argc; i++)
    child_argv[j++] = argv[i];
  child_argv[j++] = NULL;

  update_env_var_list ("LD_LIBRARY_PATH", BUNDLE_PREFIX "/lib");

  return execv (executable, child_argv);

 oom:
  if (executable)
    free (executable);

  fprintf (stderr, "Out of memory.\n");

 error_out:
  while (mount_count-- > 0)
    umount (BUNDLE_PREFIX);
  return 1;
}
