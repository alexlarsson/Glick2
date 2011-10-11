#define FUSE_USE_VERSION 26

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <glib.h>
#include <sys/mman.h>
#include <string.h>

#include "glick.h"
#include "format.h"

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
	      close (mounted_signal_fd);

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
    {
      write (mounted_signal_fd, &c_err, 1);
      close (mounted_signal_fd);
    }

  return 0;
}

int
send_message (int target_socket,
	      char *message,
	      size_t message_size,
	      int fd_to_send)
 {
   struct msghdr socket_message;
   struct iovec io_vector[1];
   struct cmsghdr *control_message = NULL;
   char ancillary_buffer[CMSG_SPACE(sizeof (int))];

   io_vector[0].iov_base = message;
   io_vector[0].iov_len = message_size;

   /* initialize socket message */
   memset (&socket_message, 0, sizeof (struct msghdr));
   socket_message.msg_iov = io_vector;
   socket_message.msg_iovlen = 1;

   memset (ancillary_buffer, 0, sizeof (ancillary_buffer));
   socket_message.msg_control = ancillary_buffer;
   socket_message.msg_controllen = sizeof (ancillary_buffer);

   /* initialize a single ancillary data element for fd passing */
   control_message = CMSG_FIRSTHDR(&socket_message);
   control_message->cmsg_level = SOL_SOCKET;
   control_message->cmsg_type = SCM_RIGHTS;
   control_message->cmsg_len = CMSG_LEN(sizeof(int));
   *((int *) CMSG_DATA(control_message)) = fd_to_send;

   return sendmsg (target_socket, &socket_message, 0);
 }

int
connect_to_socket (const char *path)
{
  struct sockaddr_un address = {0};
  int socket_fd;

  socket_fd = socket (PF_UNIX, SOCK_SEQPACKET, 0);
  if (socket_fd < 0)
    return -1;

  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof (address.sun_path), path);

  if (connect (socket_fd,
	       (struct sockaddr *) &address,
	       sizeof(struct sockaddr_un)) != 0)
    return -1;

  return socket_fd;
}

char *
map_and_verify_bundle (int fd, gsize *mapped_size)
{
  GlickBundleHeader *header;
  char *data;
  struct stat statbuf;
  guint32 header_size;
  guint32 num_slices;
  guint32 slices_offset;
  guint64 slices_size;

  if (fstat (fd, &statbuf) != 0)
    return NULL;

  if (sizeof (GlickBundleHeader) >= statbuf.st_size)
    return NULL;

  data = mmap (NULL, sizeof (GlickBundleHeader), PROT_READ,
	       MAP_PRIVATE, fd, 0);
  if (data == NULL)
    return NULL;

  header = (GlickBundleHeader *)data;
  header_size = GUINT32_FROM_LE (header->header_size);

  munmap (data, sizeof (GlickBundleHeader));

  /* Ensure that the header fits in the file */
  if (header_size >= statbuf.st_size)
    return NULL;

  /* header_size is uint32, so this can't wrap gsize */
  data = mmap (NULL, header_size, PROT_READ,
	       MAP_PRIVATE, fd, 0);
  if (data == NULL)
    return NULL;

  header = (GlickBundleHeader *)data;

  if (memcmp (header->glick_magic, GLICK_MAGIC, 8) != 0)
    {
      munmap (data, header_size);
      return NULL;
    }

  if (GUINT32_FROM_LE (header->glick_version) != GLICK_VERSION)
    {
      munmap (data, header_size);
      return NULL;
    }

  slices_offset = GUINT32_FROM_LE (header->slices_offset);
  num_slices = GUINT32_FROM_LE (header->num_slices);
  slices_size = num_slices * sizeof (GlickSliceRef);

  /* Ensure that the slice fits in the file */
  if (slices_offset >= statbuf.st_size ||
      slices_size > statbuf.st_size ||
      slices_offset > statbuf.st_size - slices_size)
    {
      munmap (data, header_size);
      return NULL;
    }

  *mapped_size = header_size;
  return data;
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
  char dummy_mountpoint[] = "/tmp/.glick_XXXXXX";
  char fd_buf[21]; // Size enough for a 64bit fd...
  int exe_fd;
  const char *homedir;
  char *glick_mount, *glick_socket, *glick_subdir;
  int socket_fd;
  ssize_t nbytes;
  GlickMountRequestMsg msg;
  GlickMountRequestReply reply;
  GlickBundleHeader *header;
  char *data;
  gsize header_size;
  char *default_executable;
  char *exec, *argv0;
  char *bundle_path;
  char *custom_executable;
  int argc_offset;

  argc_offset = 1;

  if (argc_offset >= argc)
    {
      fprintf (stderr, "No image specified\n");
      return 1;
    }
  bundle_path = argv[argc_offset++];

  custom_executable = NULL;
  if (argc - argc_offset >= 2 &&
      strcmp ("-exec", argv[argc_offset]) == 0)
    {
      custom_executable = argv[argc_offset+1];
      argc_offset += 2;
    }

  exe_fd = open (bundle_path, O_RDONLY);
  if (exe_fd == -1)
    {
      fprintf (stderr, "Unable to open %s\n", bundle_path);
      return 1;
    }

  data = map_and_verify_bundle (exe_fd, &header_size);
  if (data == NULL)
    {
      fprintf (stderr, "Invalid bundle format in file %s\n", bundle_path);
      return 1;
    }

  header = (GlickBundleHeader *)data;

  default_executable = NULL;
  if (header->exec_offset != 0)
    default_executable =
      g_strndup (data + GUINT32_FROM_LE (header->exec_offset),
		 GUINT32_FROM_LE (header->exec_size));

  munmap (data, header_size);

  homedir = g_get_home_dir ();
  glick_mount = g_build_filename (homedir, ".glick", NULL);
  glick_socket = g_build_filename (glick_mount, "socket", NULL);

  socket_fd = connect_to_socket (glick_socket);
  if (socket_fd == -1)
    {
      fprintf (stderr, "Unable to contact glick filesystem\n");
      return 1;
    }

  g_free (glick_socket);

  msg.version = 0;
  msg.padding = 0;
  msg.offset = 0;

  if (send_message (socket_fd, (char *)&msg, sizeof (msg), exe_fd) == -1)
    {
      fprintf (stderr, "Unable to send message to glick filesystem\n");
      return 1;
    }
  close (exe_fd);

  nbytes = recv (socket_fd, (char *)&reply, sizeof (reply), 0);
  if (nbytes < sizeof (reply))
    {
      fprintf (stderr, "Unexpected reply size recieved\n");
      return 1;
    }

  if (reply.result != 0)
    {
      fprintf (stderr, "Error mounting image %d\n", reply.result);
      return 1;
    }

  glick_subdir = g_build_filename (glick_mount, reply.name, NULL);

  if (pipe (fuse_mounted_pipe) != 0)
    return 1;
  if (pipe (internal_mount_done_pipe) != 0)
    return 1;
  if (mkdtemp (dummy_mountpoint) == NULL)
    return 1;

  pid = fork ();
  if (pid == 0)
    {
      size_t arg_len;
      char *bundle = g_strdup (bundle_path);

      arg_len = argv[argc-1] + strlen (argv[argc-1]) - argv[0];

      memset (argv[0], 0, arg_len);
      argv[0][arg_len] = 'x';
      snprintf (argv[0], arg_len, "glick-watcher [%s]", bundle);
      g_free (bundle);

      close (fuse_mounted_pipe[READ_SIDE]);
      close (internal_mount_done_pipe[WRITE_SIDE]);

      setpgid (0, 0);
      return run_dummy_fs ("glick-dummy", dummy_mountpoint, fuse_mounted_pipe[WRITE_SIDE], internal_mount_done_pipe[READ_SIDE]);
    }

  close (socket_fd);
  close (fuse_mounted_pipe[WRITE_SIDE]);
  close (internal_mount_done_pipe[READ_SIDE]);

  /* Wait for the fuse fs to be mounted */
  res = read (fuse_mounted_pipe[READ_SIDE], &b, 1);
  close (fuse_mounted_pipe[READ_SIDE]);

  snprintf (fd_buf, sizeof (fd_buf), "%d", internal_mount_done_pipe[WRITE_SIDE]);
  fd_buf[sizeof(fd_buf)-1] = 0; // Ensure zero termination

  exec = "/bin/sh";
  argv0 = NULL;
  if (custom_executable)
    {
      if (*custom_executable == '/')
	exec = custom_executable;
      else
	exec = g_build_filename (glick_subdir, custom_executable, NULL);
    }
  else if (default_executable)
    {
      if (*default_executable == '/')
	exec = default_executable;
      else
	{
	  exec = g_build_filename (glick_subdir, default_executable, NULL);
	  argv0 = bundle_path;
	}
    }

  if (argv0 == NULL)
    argv0 = exec;

  /* Spawn the make-private-namespace handler */
  child_argv = malloc ((1 + 5 + (argc) + 1 ) * sizeof (char *));
  i = 0;
  child_argv[i++] = LIBEXECDIR "/glick-helper";
  child_argv[i++] = glick_subdir;
  child_argv[i++] = exec;
  /* Make it write to internal_mount_done_pipe when internals mounts are set up to wake the fuse
     child */
  child_argv[i++] = "-extra";
  child_argv[i++] = dummy_mountpoint;
  child_argv[i++] = "-fd";
  child_argv[i++] = fd_buf;

  child_argv[i++] = argv0;
  for (j = argc_offset; j < argc; j++)
    child_argv[i++] = argv[j];

  child_argv[i++] = NULL;

  setenv ("BUNDLE_PREFIX", glick_subdir, TRUE);
  return execv (child_argv[0], child_argv);
}
