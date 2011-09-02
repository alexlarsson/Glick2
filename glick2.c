#define FUSE_USE_VERSION 26

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

static void
dummy_getattr (fuse_req_t req, fuse_ino_t ino,
	       struct fuse_file_info *fi)
{
  struct stat stbuf;

  (void) fi;

  if (ino != 1)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  memset (&stbuf, 0, sizeof(stbuf));
  stbuf.st_ino = ino;
  stbuf.st_mode = S_IFDIR | 0755;
  stbuf.st_nlink = 2;
  fuse_reply_attr (req, &stbuf, 1.0);
}

static void
dummy_lookup (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  fuse_reply_err (req, ENOENT);
}

static void
dummy_readdir (fuse_req_t req, fuse_ino_t ino, size_t size,
	       off_t off, struct fuse_file_info *fi)
{
  (void) fi;

  if (ino != 1)
    fuse_reply_err (req, ENOTDIR);
  else
    fuse_reply_buf (req, NULL, 0);
}

static struct fuse_lowlevel_ops dummy_oper = {
  .lookup	= dummy_lookup,
  .getattr	= dummy_getattr,
  .readdir	= dummy_readdir,
};

#define FUSERMOUNT_DIR "/usr/bin"
#define FUSERMOUNT_PROG "fusermount"

int
unmount_fuse_fs (char *mountpoint)
{
  int pid;

  pid = fork ();

  if (pid == -1)
    return -1;

  if (pid == 0)
    {
      const char *argv[] = { FUSERMOUNT_PROG, "-u", "-q", "-z",
			     "--", mountpoint, NULL };

      execv (FUSERMOUNT_DIR "/" FUSERMOUNT_PROG, (char **) argv);
      execvp (FUSERMOUNT_PROG, (char **) argv);
      _exit (1);
    }
  waitpid (pid, NULL, 0);
  return 0;
}

#define READ_SIDE 0
#define WRITE_SIDE 1

/* This mounts a dummy filesystem in the parent namespace, then waits
   for it to be mounted in a child namespace before unmounting it
   in the parent. This means the only reference to the dummy fs is
   in the child namespace, and when it dies we get the unmount event.
   This way we can keep track of when the child namespace dies.
*/
int
run_dummy_fs (char *argv0,
	      char *mountpoint,
	      int mounted_signal_fd,
	      int wait_to_unmount_fd)
{
  /* Child: Fuse implementation */
  int err = -1;
  int wrote_ok = 0;
  char b;
  char c_ok = 1;
  char c_err = 0;
  ssize_t res;
  struct fuse_chan *ch;
  char *fuse_argv[] = { NULL, "-o", "ro" };
  struct fuse_args fuse_args = {
    3,
    fuse_argv,
    0
  };

  /* Mount the filesystem */
  fuse_args.argv[0] = argv0;
  if ((ch = fuse_mount (mountpoint, &fuse_args)) != NULL)
    {
      struct fuse_session *se;

      se = fuse_lowlevel_new (&fuse_args, &dummy_oper,
			      sizeof (dummy_oper), NULL);
      if (se != NULL)
	{
	  if (fuse_set_signal_handlers (se) != -1)
	    {
	      fuse_session_add_chan (se, ch);

	      /* Mounted the filesystem, tell the parent */
	      wrote_ok = 1;
	      write (mounted_signal_fd, &c_ok, 1);

	      /* Wait for the parent to bind mount the filesystem into
	       * its own namespace */
	      res = read (wait_to_unmount_fd, &b, 1);

	      /* Unmount the fuse filesystem in the global namespace
	       * so that it will be auto-unmounted when the namespace dies */
	      unmount_fuse_fs (mountpoint);

	      /* Handle the fuse calls */
	      err = fuse_session_loop (se);
	      fuse_remove_signal_handlers (se);
	      fuse_session_remove_chan (ch);
	    }
	  fuse_session_destroy (se);
	}
      fuse_unmount (mountpoint, ch);
    }

  if (!wrote_ok)
    write (mounted_signal_fd, &c_err, 1);

  return 0;
}

int
main (int argc, char *argv[])
{
  int fuse_mounted_pipe[2];
  int internal_mount_done_pipe[2];
  int pid;
  ssize_t res;
  char b;
  char **child_argv;
  int i, j;
  char mountpoint[] = "/tmp/.glick_XXXXXX";
  char fd_buf[21]; // Size enough for a 64bit fd...

  if (pipe (fuse_mounted_pipe) != 0)
    return 1;
  if (pipe (internal_mount_done_pipe) != 0)
    return 1;
  if (mkdtemp (mountpoint) == NULL)
    return 1;

  pid = fork ();
  if (pid == 0)
    {
      close (fuse_mounted_pipe[READ_SIDE]);
      close (internal_mount_done_pipe[WRITE_SIDE]);
      return run_dummy_fs (argv[0], mountpoint, fuse_mounted_pipe[WRITE_SIDE], internal_mount_done_pipe[READ_SIDE]);
    }

  close (fuse_mounted_pipe[WRITE_SIDE]);
  close (internal_mount_done_pipe[READ_SIDE]);

  /* Wait for the fuse fs to be mounted */
  res = read (fuse_mounted_pipe[READ_SIDE], &b, 1);
  close (fuse_mounted_pipe[READ_SIDE]);

  /* Spawn the make-private-namespace handler */
  child_argv = malloc ((1 + 3 + (argc - 1) + 1 ) * sizeof (char *));
  i = 0;
  child_argv[i++] = BINDIR "/private-mount";
  child_argv[i++] = mountpoint;
  child_argv[i++] = "/bin/sh"; /* TODO: should be the fs-internal binary to run */
  /* Make it write to internal_mount_done_pipe when internals mounts are set up to wake the fuse
     child */
  child_argv[i++] = "-fd";

  snprintf (fd_buf, sizeof (fd_buf), "%d", internal_mount_done_pipe[WRITE_SIDE]);
  fd_buf[sizeof(fd_buf)] = 0; // Ensure zero termination
  child_argv[i++] = fd_buf;
  for (j = 1; j < argc; j++)
    child_argv[i++] = argv[j];
  child_argv[i++] = NULL;

  return execv (child_argv[0], child_argv);
}
