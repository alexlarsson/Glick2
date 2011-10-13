#include "config.h"

#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <sched.h>

static const char *
get_homedir (void)
{
  const char *home;

  home = getenv ("HOME");
  if (home == NULL)
    {
      /* try from the user database */
      struct passwd *user = getpwuid (getuid());
      if (user != NULL)
	home = user->pw_dir;
    }

  return home;
}

static char *
build_path (const char *dir, const char *file)
{
  char *path;

  path = malloc (strlen (dir) + 1 + strlen (file) + 1);

  if (path != NULL)
    {
      strcpy (path, dir);
      strcat (path, "/");
      strcat (path, file);
    }
  return path;
}

static void
make_symlink (const char *dest_dir, const char *dest_file,
	      const char *src_dir, const char *src_file)
{
  char *d, *s;

  d = build_path (dest_dir, dest_file);
  if (d)
    {
      s = build_path (src_dir, src_file);
      if (s)
	{
	  if (symlink (s, d) == -1 && errno != EEXIST)
	    perror ("Failed to symlink");
	  free (s);
	}
      free (d);
    }
}

static int
mount_rprivate (const char *path)
{
  return mount (path, path, NULL, MS_PRIVATE|MS_REC, NULL);
}

static int
mount_rshared (const char *path)
{
  return mount (path, path, NULL, MS_SHARED|MS_REC, NULL);
}

static int
mount_bind (const char *src, const char *dest)
{
  return mount (src, dest, NULL, MS_BIND, NULL);
}

int
main(int argc, char **argv)
{
  char *session_dir;
  const char *runtime_dir;
  const char *homedir;
  int res;

  /* The initial code is run with a high permission euid
     (at least CAP_SYS_ADMIN), so take lots of care. */

  /* Switch effective uid to the user */
  seteuid (getuid ());
  
  if (argc == 1)
    {
      fprintf (stderr, "No executable specified\n");
      return 1;
    }


  homedir = get_homedir ();
  if (homedir == NULL)
    goto error;
  
  runtime_dir = getenv ("XDG_RUNTIME_DIR");
  if (runtime_dir != NULL)
    {
      session_dir = build_path (runtime_dir, "sessiondir");
      if (session_dir == NULL)
	{
	  fprintf (stderr, "Out of memory\n");
	  goto error;
	}
      
      if (mkdir (session_dir, 0700) == -1 && errno != EEXIST)
	{
	  fprintf (stderr, "Unable to create temporary session directory\n");
	  goto error;
	}
    }
  else
    {
      /* Fall back to /tmp dir */
      char tmpdir[] = "/tmp/.sessionXXXXXX";
      session_dir = mkdtemp(tmpdir);
      if (session_dir == NULL)
	{
	  fprintf (stderr, "Unable to create temporary session directory\n");
	  goto error;
	}
    }

  if (setuid (0) == -1)
    {
      perror ("Unable to regain root priviledges");
      goto error;
    }

  /* Create a new mount namespace for the session */
  res = unshare (CLONE_NEWNS);
  if (res != 0)
    {
      perror ("Creating new namespace failed");
      goto error;
   }

  /* Start with a clean slate, all mounts private */
  res = mount_rprivate ("/");
  if (res != 0)
    {
      perror ("Failed to make rprivate");
      goto error;
     }

  /* Make /opt/session point to the session directory.
     This will not propagate dure to the rprivate above.  */
  res = mount_bind (session_dir, SESSION_PREFIX);
  if (res != 0)
    {
      perror ("Failed to bind session dir");
      goto error;
    }

  /* Make the whole new namespace rshared so that later session
     mounts are propagated to child bundle namespaces */
  res = mount_rshared ("/");
  if (res != 0)
    {
      perror ("Failed to make rshared");
      goto error;
    }

  /* Except the session dir. */
  res = mount (SESSION_PREFIX, SESSION_PREFIX,
	       NULL, MS_PRIVATE, NULL);
  if (res != 0)
    {
      perror ("Failed to make session dir private");
      goto error;
    }

  /* Now we have everything we need CAP_SYS_ADMIN for, so drop setuid */
  setuid (getuid ());

  make_symlink (session_dir, "bundles",
		homedir, ".glick/bundles");
  make_symlink (session_dir, "exports",
		homedir, ".glick/exports");
  
  return execvp (argv[1], argv+1);
 error:
  /* Now we have everything we need CAP_SYS_ADMIN for, so drop setuid */
  setuid (getuid ());

  return execvp (argv[1], argv+1);
}
