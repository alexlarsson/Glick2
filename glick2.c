#define FUSE_USE_VERSION 26

#include <sys/types.h>
#include <sys/wait.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "sh.h"

static const char *shell_name = "sh";

static int
glick_stat (fuse_ino_t ino, struct stat *stbuf)
{
  stbuf->st_ino = ino;
  switch (ino) {
  case 1:
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    break;

  case 2:
    stbuf->st_mode = S_IFREG | 0744;
    stbuf->st_nlink = 1;
    stbuf->st_size = binsh_size;
    break;

  default:
    return -1;
  }
  return 0;
}

static void
glick_getattr (fuse_req_t req, fuse_ino_t ino,
	       struct fuse_file_info *fi)
{
  struct stat stbuf;

  (void) fi;

  memset(&stbuf, 0, sizeof(stbuf));
  if (glick_stat(ino, &stbuf) == -1)
    fuse_reply_err(req, ENOENT);
  else
    fuse_reply_attr(req, &stbuf, 1.0);
}

static void
glick_lookup (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  struct fuse_entry_param e;

  if (parent != 1 || strcmp(name, shell_name) != 0)
    fuse_reply_err(req, ENOENT);
  else {
    memset(&e, 0, sizeof(e));
    e.ino = 2;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;
    glick_stat(e.ino, &e.attr);

    fuse_reply_entry(req, &e);
  }
}

struct dirbuf {
  char *p;
  size_t size;
};

static void
dirbuf_add (fuse_req_t req, struct dirbuf *b, const char *name,
	    fuse_ino_t ino)
{
  struct stat stbuf;
  size_t oldsize = b->size;
  b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
  b->p = (char *) realloc(b->p, b->size);
  memset(&stbuf, 0, sizeof(stbuf));
  stbuf.st_ino = ino;
  fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
		    b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int
reply_buf_limited (fuse_req_t req, const char *buf, size_t bufsize,
		   off_t off, size_t maxsize)
{
  if (off < bufsize)
    return fuse_reply_buf(req, buf + off,
			  min(bufsize - off, maxsize));
  else
    return fuse_reply_buf(req, NULL, 0);
}

static void
glick_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
	      off_t off, struct fuse_file_info *fi)
{
  (void) fi;

  if (ino != 1)
    fuse_reply_err(req, ENOTDIR);
  else {
    struct dirbuf b;

    memset(&b, 0, sizeof(b));
    dirbuf_add(req, &b, ".", 1);
    dirbuf_add(req, &b, "..", 1);
    dirbuf_add(req, &b, shell_name, 2);
    reply_buf_limited(req, b.p, b.size, off, size);
    free(b.p);
  }
}

static void
glick_open(fuse_req_t req, fuse_ino_t ino,
	   struct fuse_file_info *fi)
{
  fi->keep_cache = 1;
  if (ino != 2)
    fuse_reply_err(req, EISDIR);
  else if ((fi->flags & 3) != O_RDONLY)
    fuse_reply_err(req, EACCES);
  else
    fuse_reply_open(req, fi);
}

static void
glick_read (fuse_req_t req, fuse_ino_t ino, size_t size,
	    off_t off, struct fuse_file_info *fi)
{
  (void) fi;

  assert(ino == 2);
  reply_buf_limited(req, binsh, binsh_size, off, size);
}

static struct fuse_lowlevel_ops glick_oper = {
	.lookup		= glick_lookup,
	.getattr	= glick_getattr,
	.readdir	= glick_readdir,
	.open		= glick_open,
	.read		= glick_read,
};

#define FUSERMOUNT_DIR "/usr/bin"
#define FUSERMOUNT_PROG "fusermount"

int 
unmount_fuse_fs (char *mountpoint) 
{
  int pid;

  pid = fork();

  if (pid == -1)
    return -1;

  if (pid == 0) {
    const char *argv[] = { FUSERMOUNT_PROG, "-u", "-q", "-z",
			   "--", mountpoint, NULL };
    
    execv(FUSERMOUNT_DIR "/" FUSERMOUNT_PROG, (char **) argv);
    execvp(FUSERMOUNT_PROG, (char **) argv);
    _exit(1);
  }
  waitpid(pid, NULL, 0);
  return 0;
}

int main(int argc, char *argv[])
{
  struct fuse_chan *ch;
  int err = -1;
  int fuse_mounted_pipe[2];
  int internal_mount_done_pipe[2];
  char tempdir[] = "/tmp/.glick2XXXXXX";
  int pid;
  char c_ok = 1;
  char c_err = 0;
  char b;
  ssize_t res;
  char **child_argv;
  int i, j;
  char *fuse_argv[] = { NULL, "-o", "ro" };
  struct fuse_args fuse_args = {
    3,
    fuse_argv,
    0
  };
  char fd_buf[21]; // Size enough for a 64bit fd...

  fuse_args.argv[0] = argv[0];

  if (pipe (fuse_mounted_pipe) != 0)
    return 1;
  if (pipe (internal_mount_done_pipe) != 0)
    return 1;
  if (mkdtemp (tempdir) == NULL) {
    return 1;
  }

  pid = fork ();
  if (pid == 0) {
    /* Child: Fuse implementation */

    close (fuse_mounted_pipe[0]);
    close (internal_mount_done_pipe[1]);
    
    /* Mount the filesystem */

    if ((ch = fuse_mount(tempdir, &fuse_args)) != NULL) {
      struct fuse_session *se;
      int wrote_ok = 0;

      se = fuse_lowlevel_new (&fuse_args, &glick_oper,
			      sizeof(glick_oper), NULL);
      if (se != NULL) {
	if (fuse_set_signal_handlers(se) != -1) {
	  fuse_session_add_chan(se, ch);

	  /* Mounted the filesystem, tell the parent */
	  wrote_ok = 1;
	  write (fuse_mounted_pipe[1], &c_ok, 1);

	  /* Wait for the parent to bind mount the filesystem into
	   * its own namespace */
	  res = read (internal_mount_done_pipe[0], &b, 1);

	  /* Unmount the fuse filesystem in the global namespace
	   * so that it will be auto-unmounted when the namespace dies */
	  unmount_fuse_fs (tempdir);

	  /* Handle the fuse calls */
	  err = fuse_session_loop(se);
	  fuse_remove_signal_handlers(se);
	  fuse_session_remove_chan(ch);
	}
	fuse_session_destroy(se);
      }
      fuse_unmount(tempdir, ch);
      if (!wrote_ok)
	write (fuse_mounted_pipe[1], &c_err, 1);
    }
    return 0;
  } else {
    close (fuse_mounted_pipe[1]);
    close (internal_mount_done_pipe[0]);

    /* Wait for the fuse fs to be mounted */
    res = read (fuse_mounted_pipe[0], &b, 1);
    close (fuse_mounted_pipe[0]);

    /* Spawn the make-private-namespace handler */
    child_argv = malloc ((1 + 3 + (argc - 1) + 1 ) * sizeof (char *));
    i = 0;
    child_argv[i++] = BINDIR "/private-mount";
    child_argv[i++] = tempdir;
    child_argv[i++] = "/bin/sh"; /* TODO: should be the fs-internal binary to run */
    /* Make it write to internal_mount_done_pipe when internals mounts are set up to wake the fuse
       child */
    child_argv[i++] = "-fd";

    snprintf (fd_buf, sizeof (fd_buf), "%d", internal_mount_done_pipe[1]);
    fd_buf[sizeof(fd_buf)] = 0; // Ensure zero termination
    child_argv[i++] = fd_buf;
    for (j = 1; j < argc; j++)
      child_argv[i++] = argv[j];
    child_argv[i++] = NULL;

    return execv (child_argv[0], child_argv);
  }
  return err ? 1 : 0;
}
