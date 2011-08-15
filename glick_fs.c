#define FUSE_USE_VERSION 26

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <assert.h>
#include <glib.h>

/* Inodes:
   32 bits

   Root:

   00000000000000000000000000000001

   Socket:

   00000000000000000000000000000010

   Toplevel Directory:

                   +- 16bit glick mount id (>=3)
                   v
   0000000000000000yyyyyyyyyyyyyyyy

   GlickMount Directory:

    +- 15bit atom per glick mount (!= 0)
    |              +- 16bit glick mount id (>=3)
    v              v
   0xxxxxxxxxxxxxxxyyyyyyyyyyyyyyyy

   File:

    +- 15bit slice id  
    |              +- 16bit fixed inode in slice
    v              v
   1xxxxxxxxxxxxxxxyyyyyyyyyyyyyyyy

*/

typedef struct {
  char *name; // SHA-1 of full bundle
  int refs;
  unsigned long id;

  /* Two-way mapping between inodes and paths
     for directories that we've looked up so 
     far (that had entries) */
  GHashTable *inode_to_path;
  GHashTable *path_to_inode;
  int next_dir_inode;

  void *pointer_to_slices;
} GlickMount;

typedef struct {
  int fd;
  GlickMount *mount;
}  GlickMountRef;

#define ROOT_INODE 1
#define SOCKET_INODE 2
#define SOCKET_NAME "socket"

#define FILE_INODE_MASK 0x80000000
#define INODE_IS_FILE(ino) (((ino) & FILE_INODE_MASK) != 0)
#define DIRECTORY_INODE_ID_MASK 0x0000FFFF
#define DIRECTORY_INODE_SUBDIR_MASK 0x7FFF0000
#define DIRECTORY_INODE_SUBDIR_SHIFT 16
#define DIRECTORY_INODE_GET_ID(x) ((x) & DIRECTORY_INODE_ID_MASK)
#define DIRECTORY_INODE_GET_SUBDIR(x) (((x) & DIRECTORY_INODE_SUBDIR_MASK) >> DIRECTORY_INODE_SUBDIR_SHIFT)
#define DIRECTORY_INODE(id, subdir) ((id) | ((subdir) << DIRECTORY_INODE_SUBDIR_SHIFT))
#define MOUNT_INODE_FROM_ID(id) DIRECTORY_INODE((id), 0)

static GHashTable *glick_mounts_by_id; /* id -> GlickMount */
static GHashTable *glick_mounts_by_name; /* name -> GlickMount */
static GList *glick_mounts = NULL; /* list of GlickMount */
static GList *glick_mount_refs = NULL; /* list of GlickMountRefs */
static int next_glick_mount_id = 2;

static int master_socket_ready_pipe = 0;
static int socket_created = 0;
static int master_socket;

int
recv_socket_message (int socket_fd,
		     char *buffer,
		     size_t buffer_size,
		     int *recieved_fd)
{
  struct msghdr socket_message = { 0 };
  struct iovec io_vector[1];
  struct cmsghdr *control_message = NULL;
  ssize_t res;
  char ancillary_buffer[CMSG_SPACE(sizeof (int))];

  *recieved_fd = -1;

  memset (ancillary_buffer, 0, sizeof (ancillary_buffer));

  io_vector[0].iov_base = buffer;
  io_vector[0].iov_len = buffer_size;
  socket_message.msg_iov = io_vector;
  socket_message.msg_iovlen = 1;
  socket_message.msg_control = ancillary_buffer;
  socket_message.msg_controllen = sizeof (ancillary_buffer);

  res = recvmsg (socket_fd, &socket_message,
		 MSG_CMSG_CLOEXEC);
  if (res < 0)
    return -1;

  if ((socket_message.msg_flags & MSG_CTRUNC) == MSG_CTRUNC)
    {
      /* we did not provide enough space for the ancillary element array */
      return -1;
    }

  /* Find the first fd */
   for (control_message = CMSG_FIRSTHDR(&socket_message);
	control_message != NULL;
	control_message = CMSG_NXTHDR(&socket_message, control_message))
     {
       if( (control_message->cmsg_level == SOL_SOCKET) &&
	   (control_message->cmsg_type == SCM_RIGHTS) )
	 {
	   *recieved_fd = *((int *) CMSG_DATA(control_message));
	   break;
	 }
     }

  return res;
 }

static int 
glick_fs_stat (fuse_ino_t ino, struct stat *stbuf)
{
  gulong id, subdir;
  GlickMount *mount;

  stbuf->st_ino = ino;

  if (!INODE_IS_FILE (ino)) 
    {
      /* Directory */
      switch (ino) 
	{
	case 0:
	  return -1;

	case ROOT_INODE:
	  stbuf->st_mode = S_IFDIR | 0755;
	  stbuf->st_nlink = 2;
	  break;

	case SOCKET_INODE:
	  stbuf->st_mode = S_IFSOCK | 0777;
	  stbuf->st_nlink = 1;
	  stbuf->st_size = 0;
	  break;

	default:
	  id = DIRECTORY_INODE_GET_ID (ino);
	  subdir = DIRECTORY_INODE_GET_SUBDIR (ino);

	  mount = g_hash_table_lookup (glick_mounts_by_id, GINT_TO_POINTER (id));
	  if (mount == NULL)
	    return -1;

	  if (subdir == 0) 
	    {
	      /* Toplevel of "submount" */
	      stbuf->st_mode = S_IFDIR | 0755;
	      stbuf->st_nlink = 2;
	    }
	  else
	    {
	      /* TODO: Handle dir inside glick mount */
	      return -1;
	    }
	}
    }
  else
    {
      /* Regular File */
      return -1;
    }

  return 0;
}

static void
glick_fs_getattr (fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
  struct stat stbuf;

  g_print ("glick_fs_getattr %d\n", (int)ino);
  (void) fi;

  memset (&stbuf, 0, sizeof(stbuf));
  if (glick_fs_stat (ino, &stbuf) == -1)
    fuse_reply_err (req, ENOENT);
  else
    fuse_reply_attr (req, &stbuf, 1.0);
}

static void
glick_fs_lookup (fuse_req_t req, fuse_ino_t parent,
		 const char *name)
{
  struct fuse_entry_param e = { 0 };
  GlickMount *mount;

  g_print ("glick_fs_lookip %d %s\n", (int)parent, name);
 
  if (parent == ROOT_INODE)
    {
      if (socket_created &&
	  strcmp (SOCKET_NAME, name) == 0)
	{
	  e.ino = SOCKET_INODE;
	  glick_fs_stat (e.ino, &e.attr);
	  fuse_reply_entry (req, &e);
	  return;
	}
      mount = g_hash_table_lookup (glick_mounts_by_name, name);
      if (mount)
	{
	  e.ino = MOUNT_INODE_FROM_ID (mount->id);
	  glick_fs_stat (e.ino, &e.attr);
	  fuse_reply_entry (req, &e);
	  return;
	}
    }
  else
    {
      /* Handle lookups inside subdirs */
    }

  fuse_reply_err (req, ENOENT);
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

  b->size += fuse_add_direntry (req, NULL, 0, name, NULL, 0);
  b->p = (char *) realloc (b->p, b->size);
  memset (&stbuf, 0, sizeof (stbuf));
  stbuf.st_ino = ino;
  fuse_add_direntry (req, b->p + oldsize, b->size - oldsize, name, &stbuf,
		     b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int
reply_buf_limited (fuse_req_t req, const char *buf, size_t bufsize,
		   off_t off, size_t maxsize)
{
  if (off < bufsize)
    return fuse_reply_buf (req, buf + off,
			   min (bufsize - off, maxsize));
  else
    return fuse_reply_buf (req, NULL, 0);
}

static void
glick_fs_readdir (fuse_req_t req, fuse_ino_t ino, size_t size,
		  off_t off, struct fuse_file_info *fi)
{
  struct dirbuf b = { 0 };
  GList *l;

  g_print ("glick_fs_readdir %d\n", (int)ino);
  (void) fi;

  if (INODE_IS_FILE (ino) || ino == SOCKET_INODE)
    {
      fuse_reply_err (req, ENOTDIR);
      return;
    }
  
  dirbuf_add (req, &b, ".", ino);

  if (ino == ROOT_INODE)
    {
      dirbuf_add (req, &b, "..", ROOT_INODE);
      if (socket_created)
	dirbuf_add (req, &b, SOCKET_NAME, SOCKET_INODE);
      for (l = glick_mounts; l != NULL; l = l->next)
	{
	  GlickMount *mount = l->data;
	  
	  dirbuf_add (req, &b, mount->name, 
		      MOUNT_INODE_FROM_ID(mount->id));
	}
      reply_buf_limited (req, b.p, b.size, off, size);
    }
  else
    {
      gulong id = DIRECTORY_INODE_GET_ID (ino);
      gulong subdir = DIRECTORY_INODE_GET_ID (ino);
      GlickMount *mount;

      mount = g_hash_table_lookup (glick_mounts_by_id, GINT_TO_POINTER (id));
      if (mount == NULL)
	{
	  fuse_reply_err (req, ENOENT);
	  goto out;
	}

      if (subdir == 0)
	{
	  dirbuf_add (req, &b, "..", ROOT_INODE);
	  reply_buf_limited (req, b.p, b.size, off, size);
	}
      else
	{
	  /* TODO: Handle real dirs */
	  fuse_reply_err (req, ENOENT);
	}
    }

 out:
  free (b.p);
}

static void
glick_fs_open (fuse_req_t req, fuse_ino_t ino,
	       struct fuse_file_info *fi)
{
  g_print ("glick_fs_open %d\n", (int)ino);

  if (!INODE_IS_FILE (ino)) 
    fuse_reply_err (req, EISDIR);
  else if ((fi->flags & 3) != O_RDONLY)
    fuse_reply_err (req, EACCES);
  else
    {
      /* TODO: Handle file data */
      fuse_reply_err (req, EACCES);
      /* fuse_reply_open(req, fi); */
    }
}

static void
glick_fs_read (fuse_req_t req, fuse_ino_t ino, size_t size,
	       off_t off, struct fuse_file_info *fi)
{
  char *data = "test";

  (void) fi;
  g_print ("glick_fs_read\n");

  reply_buf_limited (req, data, strlen (data), off, size);
}

static void
glick_fs_mknod (fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode, dev_t rdev)
{
  struct fuse_entry_param e = {0};

  g_print ("glick_fs_mknod %d %s %xd %xd\n", (int)parent, name, mode, (int)rdev);

  if (parent != ROOT_INODE ||
      strcmp (SOCKET_NAME, name) != 0)
    {
      fuse_reply_err (req, EPERM);
      return;
    }

  if (socket_created) 
    {
      fuse_reply_err (req, EEXIST);
      return;
    }

  socket_created = TRUE;
  e.ino = SOCKET_INODE;
  e.attr_timeout = 1.0;
  e.entry_timeout = 1.0;
  glick_fs_stat (e.ino, &e.attr);

  fuse_reply_entry (req, &e);
}

static struct
fuse_lowlevel_ops glick_fs_oper = {
  .lookup	= glick_fs_lookup,
  .getattr	= glick_fs_getattr,
  .readdir	= glick_fs_readdir,
  .open		= glick_fs_open,
  .read		= glick_fs_read,
  .mknod	= glick_fs_mknod,
};

int
main_loop (struct fuse_session *se)
{
  int res = 0;
  struct fuse_chan *ch = fuse_session_next_chan (se, NULL);
  int fuse_fd = fuse_chan_fd (ch);
  size_t bufsize = fuse_chan_bufsize (ch);
  char *buf = (char *) malloc (bufsize);
  struct pollfd polls[2];

  if (!buf)
    {
      fprintf(stderr, "fuse: failed to allocate read buffer\n");
      return -1;
    }

  while (!fuse_session_exited (se))
    {
      struct fuse_chan *tmpch = ch;
      int i;

      i = 0;
      polls[i].fd = fuse_fd;
      polls[i].events = POLLIN;
      polls[i].revents = 0;
      i++;

      if (master_socket_ready_pipe != 0)
	polls[i].fd = master_socket_ready_pipe;
      else
	polls[i].fd = master_socket;
      polls[i].events = POLLIN;
      polls[i].revents = 0;
      i++;

      poll (polls, i, -1);

      if (polls[0].revents != 0)
	{
	  res = fuse_chan_recv (&tmpch, buf, bufsize);
	  if (res == -EINTR)
	    continue;
	  if (res <= 0)
	    break;
	  fuse_session_process (se, buf, res, tmpch);
	}

      if (master_socket_ready_pipe != 0 &&
	  polls[1].revents != 0)
	{
	  res = listen (master_socket, 5);
	  if (res == -1)
	    perror ("listen");

	  close (master_socket_ready_pipe);
	  master_socket_ready_pipe = 0;
	}
      else if (master_socket_ready_pipe == 0 &&
	  polls[1].revents != 0)
	{
	  int res, passed_fd;
	  char buffer[128];

	  res = accept (master_socket, NULL, NULL);
	  g_print ("accept: %d\n", res);
	  if (res == -1)
	    perror ("accept");
	  res = recv_socket_message (res, buffer, sizeof (buffer), &passed_fd);
	  g_print ("recvs: %d %d\n", res, passed_fd);
	  write (passed_fd, "pong\n", 5);
	}
    }

  free (buf);
  fuse_session_reset (se);
  return res < 0 ? -1 : 0;
}

int
main (int argc, char *argv[])
{
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  struct fuse_chan *ch;
  char *mountpoint;
  int err = -1;

  glick_mounts_by_id = g_hash_table_new (g_int_hash, g_int_equal);
  glick_mounts_by_name = g_hash_table_new (g_str_hash, g_str_equal);

  if (fuse_parse_cmdline (&args, &mountpoint, NULL, NULL) != -1 &&
      (ch = fuse_mount (mountpoint, &args)) != NULL)
    {
      struct fuse_session *se;

      se = fuse_lowlevel_new (&args, &glick_fs_oper,
			      sizeof glick_fs_oper, NULL);
      if (se != NULL)
	{
	  if (fuse_set_signal_handlers (se) != -1)
	    {
	      int sync_pipe[2];
	      pid_t pid;
	      char c = 'x';
	      struct sockaddr_un local;
	      int len;

	      fuse_session_add_chan (se, ch);

	      pipe (sync_pipe);
	      master_socket_ready_pipe = sync_pipe[0];
	      master_socket = socket (AF_UNIX, SOCK_SEQPACKET, 0);

	      pid = fork ();
	      if (pid == 0) {
		char *socket_path;
		int res;

		close (sync_pipe[0]);

		socket_path = g_build_filename (mountpoint, SOCKET_NAME, NULL);

		local.sun_family = AF_UNIX;
		strcpy (local.sun_path, socket_path);
		len = strlen (local.sun_path) + sizeof (local.sun_family);

		g_free (socket_path);

		res = bind (master_socket, (struct sockaddr *)&local, len);
		if (res == -1)
		  perror ("bind");

		write (sync_pipe[1], &c, 1);
		close (sync_pipe[1]);

		/* child */
		_exit (0);
		return 0;
	      }
	      close (sync_pipe[1]);

	      err = main_loop (se);
	      fuse_remove_signal_handlers (se);
	      fuse_session_remove_chan (ch);
	    }
	  fuse_session_destroy (se);
	}
      fuse_unmount (mountpoint, ch);
    }
  fuse_opt_free_args (&args);

  return err ? 1 : 0;
}
