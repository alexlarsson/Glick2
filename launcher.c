#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>
#include <X11/Xlib.h>

static gboolean csh_syntax = FALSE;
static gboolean bash_syntax = FALSE;
static gboolean exit_with_session = FALSE;
static GPid fuse_pid;

static void
print_updated_var (const char *var, const char *prefix, const char *dir, const char *default_dir)
{
  char *value;
  const char *env;

  env = getenv (var);
  if (env == NULL)
    value = g_strconcat (prefix, dir, ":", default_dir, NULL);
  else
    value = g_strconcat (prefix, dir, ":", env, NULL);

  if (csh_syntax)
    g_print ("setenv %s '%s';\n", var, value);
  else if (bash_syntax)
    {
      g_print ("%s='%s';\n", var, value);
      g_print ("export %s;\n", var);
    }
  else
    g_print ("%s=%s\n", var, value);

}

static void
usage (int ecode)
{
  g_printerr ("glick-launch [--version] [--help] [--sh-syntax] [--csh-syntax] [--exit-with-session]\n");
  exit (ecode);
}

Display *xdisplay = NULL;

static void
unmount_and_exit (int res)
{
  kill (fuse_pid, SIGHUP);
  sleep (3);
  kill (fuse_pid, SIGKILL);
  exit (res);
}

static int
x_io_error_handler (Display *xdisplay)
{
  unmount_and_exit (0);
  return 0;
}

static int got_sighup = FALSE;

static void
signal_handler (int sig)
{
  switch (sig)
    {
#ifdef SIGHUP
    case SIGHUP:
#endif
    case SIGINT:
    case SIGTERM:
      got_sighup = TRUE;
      break;
    }
}

static void
babysit (void)
{
  pid_t pid;
  int dev_null_fd;
  int x_fd;
  int tty_fd;
  fd_set read_set;
  fd_set err_set;
  struct sigaction act;
  sigset_t empty_mask;

  if (chdir ("/") < 0)
    {
      g_printerr ("Could not change to root directory\n");
      exit (1);
    }

  dev_null_fd = open ("/dev/null", O_RDWR);
  if (dev_null_fd >= 0)
    {
      dup2 (dev_null_fd, 1);
      dup2 (dev_null_fd, 2);
    }

  pid = fork ();
  if (pid < 0)
    {
      g_printerr ("fork failed\n");
      exit (1);
    }

  if (pid != 0)
    return;

  /* install SIGHUP handler */
  got_sighup = FALSE;
  sigemptyset (&empty_mask);
  act.sa_handler = signal_handler;
  act.sa_mask    = empty_mask;
  act.sa_flags   = 0;
  sigaction (SIGHUP,  &act, NULL);
  sigaction (SIGTERM,  &act, NULL);
  sigaction (SIGINT,  &act, NULL);

  if (isatty (0))
    tty_fd = 0;
  else
    tty_fd = -1;

  xdisplay = XOpenDisplay (NULL);
  XSetIOErrorHandler (x_io_error_handler);
  x_fd = ConnectionNumber (xdisplay);

  while (TRUE)
    {
      /* Dump events on the floor, and let
       * IO error handler run if we lose
       * the X connection. It's important to
       * run this before going into select() since
       * we might have queued outgoing messages or
       * events.
       */
      while (XPending (xdisplay))
	{
	  XEvent ignored;
	  XNextEvent (xdisplay, &ignored);
	}

      FD_ZERO (&read_set);
      FD_ZERO (&err_set);

      if (tty_fd >= 0)
	{
	  FD_SET (tty_fd, &read_set);
	  FD_SET (tty_fd, &err_set);
	}

      if (x_fd >= 0)
	{
	  FD_SET (x_fd, &read_set);
	  FD_SET (x_fd, &err_set);
	}

      select (MAX (tty_fd, x_fd) + 1,
	      &read_set, NULL, &err_set, NULL);

      if (got_sighup)
	unmount_and_exit (0);

      /* X Events will be processed before we select again */

      if (tty_fd >= 0)
	{
	  if (FD_ISSET (tty_fd, &read_set))
	    {
	      int bytes_read;
	      char discard[512];

	      bytes_read = read (tty_fd, discard, sizeof (discard));

	      if (bytes_read == 0)
		unmount_and_exit (0); /* EOF */
	      else if (bytes_read < 0 && errno != EINTR)
		unmount_and_exit (0);
	    }
	  else if (FD_ISSET (tty_fd, &err_set))
	    unmount_and_exit (0);
	}
    }

  unmount_and_exit (0);
}

int
main (int argc, char *argv[])
{
  GError *error = NULL;
  const char *homedir;
  char *exports;
  int i;
  char *args[] = { NULL, NULL };

  for (i = 1; i < argc; i++)
    {
      const char *arg = argv[i];

      if (strcmp (arg, "--help") == 0 ||
	  strcmp (arg, "-h") == 0 ||
	  strcmp (arg, "-?") == 0)
	usage (0);
      else if (strcmp (arg, "-c") == 0 ||
	       strcmp (arg, "--csh-syntax") == 0)
	csh_syntax = TRUE;
      else if (strcmp (arg, "-s") == 0 ||
	       strcmp (arg, "--sh-syntax") == 0)
	bash_syntax = TRUE;
      else if (strcmp (arg, "--exit-with-session") == 0)
	exit_with_session = TRUE;
      else
	{
	  g_printerr ("Unknown argument %s\n", arg);
	  usage (1);
	}
    }

  args[0] = BINDIR "/glick-fs";
  if (!g_spawn_async (NULL, args, NULL,
		      G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
		      NULL, NULL,
		      &fuse_pid,
		      &error))
    {
      g_printerr ("Can't spawn glick-fs\n");
      return 1;
    }

  homedir = g_get_home_dir ();
  exports = g_build_filename (homedir, ".glick", "exports", NULL);

  print_updated_var ("XDG_CONFIG_DIRS", exports, "/etc", "/etc/xdg");
  print_updated_var ("XDG_DATA_DIRS", exports, "/share", "/usr/share");

  if (exit_with_session)
    babysit ();

  return 0;
}
