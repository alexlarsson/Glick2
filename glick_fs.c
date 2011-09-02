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

#include "glick.h"

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
  int ref_count;
  uint32_t id;
  int fd;
  off_t file_size;
  off_t offset;
  char *data;
  size_t data_len;
} GlickSlice;

typedef struct {
  char *name;
  int ref_count;
  unsigned long id;

  /* Two-way mapping between inodes and paths
     for directories that we've looked up so
     far (that had entries) */
  GHashTable *inode_to_path;
  GHashTable *path_to_inode;
  int next_dir_inode;

  GList *slices;
} GlickMount;

typedef struct {
  int socket_fd;
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
#define FILE_INODE_SLICE_SHIFT 16
#define FILE_INODE_LOCAL_MASK 0x0000FFFF
#define FILE_INODE_SLICE_MASK 0x7FFF0000
#define FILE_INODE(slice_id, local_inode) (FILE_INODE_MASK | ((slice_id) << FILE_INODE_SLICE_SHIFT) | (local_inode))
#define FILE_INODE_GET_LOCAL(x) ((x) & FILE_INODE_LOCAL_MASK)
#define FILE_INODE_GET_SLICE(x) (((x) & FILE_INODE_SLICE_MASK) >> FILE_INODE_SLICE_SHIFT)
#define MAX_SLICE_ID 0x8fff
#define MAX_MOUNT_ID 0xffff

static GHashTable *glick_mounts_by_id; /* id -> GlickMount */
static GHashTable *glick_mounts_by_name; /* name -> GlickMount */
static GList *glick_mounts = NULL; /* list of GlickMount */
static GList *glick_mount_refs = NULL; /* list of GlickMountRefs */
static int next_glick_mount_id = 3;

static GList *glick_slices = NULL; /* list of GlickSlice */
static GHashTable *glick_slices_by_id; /* id -> GlickSlice */
static uint32_t next_glick_slice_id = 1;

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
    {
      perror ("recvmsg");
      return -1;
    }

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
  gulong id, subdir, local;
  GlickMount *mount;
  GlickSlice *slice;

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
      id = FILE_INODE_GET_SLICE (ino);

      slice = g_hash_table_lookup (glick_slices_by_id, GINT_TO_POINTER (id));
      if (slice == NULL)
	return -1;

      local = FILE_INODE_GET_LOCAL (ino);

      /* TODO: Replace with real slice lookup */
      if (local == 0)
	{
	  /* The "file" file */
	  stbuf->st_mode = S_IFREG | 0744;
	  stbuf->st_nlink = 1;
	  stbuf->st_size = slice->file_size;
	}
      else
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
  int mount_id;
  int parent_subdir;
  GlickMount *mount;

  g_print ("glick_fs_lookup, parent %d '%s'\n", (int)parent, name);

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
      mount_id = DIRECTORY_INODE_GET_ID(parent);
      parent_subdir = DIRECTORY_INODE_GET_SUBDIR(parent);

      mount = (GlickMount *)g_hash_table_lookup (glick_mounts_by_id, GINT_TO_POINTER (mount_id));
      g_print ("Lookup mount: %p, subdir: %d\n", mount, parent_subdir);
      if (mount != NULL)
	{
	  /* Handle lookups inside subdirs */

	  /* TODO: Replace with real slice lookup */

	  if (parent_subdir == 0 &&
	      strcmp (name, "file") == 0)
	    {
	      GlickSlice *slice = mount->slices->data;
	      e.ino = FILE_INODE(slice->id, 0);
	      glick_fs_stat (e.ino, &e.attr);
	      g_print ("replying with 'file' inode\n");
	      fuse_reply_entry (req, &e);
	      return;
	    }
	}
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
      gulong subdir = DIRECTORY_INODE_GET_SUBDIR (ino);
      GlickMount *mount;

      mount = g_hash_table_lookup (glick_mounts_by_id, GINT_TO_POINTER (id));
      g_print ("readdir, mount: %p\n", mount);
      if (mount == NULL)
	{
	  fuse_reply_err (req, ENOENT);
	  goto out;
	}

      if (subdir == 0)
	{
	  GlickSlice *slice = mount->slices->data;

	  dirbuf_add (req, &b, "..", ROOT_INODE);
	  dirbuf_add (req, &b, "file", FILE_INODE(slice->id, 0));
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
  GlickSlice *slice;
  int id, local;

  fi->keep_cache = 1;

  g_print ("glick_fs_open %d\n", (int)ino);

  if (!INODE_IS_FILE (ino))
    fuse_reply_err (req, EISDIR);
  else if ((fi->flags & 3) != O_RDONLY)
    fuse_reply_err (req, EACCES);
  else
    {
      id = FILE_INODE_GET_SLICE (ino);

      slice = g_hash_table_lookup (glick_slices_by_id, GINT_TO_POINTER (id));
      if (slice == NULL)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}

      local = FILE_INODE_GET_LOCAL (ino);
      /* TODO: Replace with real slice lookup */
      if (local == 0)
	{
	  fi->fh = slice->fd;
	  fuse_reply_open (req, fi);
	}
      else
	fuse_reply_err (req, EACCES);
    }
}

static void
glick_fs_read (fuse_req_t req, fuse_ino_t ino, size_t size,
	       off_t off, struct fuse_file_info *fi)
{
  char *buf;
  ssize_t res;

  (void) fi;
  g_print ("glick_fs_read\n");

  buf = malloc (size);
  res = pread (fi->fh, buf, size, off);

  if (res >= 0)
    fuse_reply_buf (req, buf, res);
  else
    fuse_reply_buf (req, NULL, 0);
  free (buf);
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

/* Looks up or creates a new slice */
GlickSlice *
glick_slice_create (int fd,
		    off_t offset)
{
  GlickSlice *slice;
  struct stat statbuf;

  if (fstat (fd, &statbuf) != 0)
    return NULL;

  slice = g_new0 (GlickSlice, 1);

  slice->id = next_glick_slice_id++;

  if (slice->id > MAX_SLICE_ID)
    {
      g_warning ("Out of slice ids\n");
      g_free (slice);
      return NULL;
    }

  slice->ref_count = 1;
  slice->fd = dup (fd);
  slice->file_size = statbuf.st_size;
  slice->offset = offset;

  slice->data = NULL;
  slice->data_len = 0;

  glick_slices = g_list_prepend (glick_slices, slice);
  g_hash_table_insert (glick_slices_by_id, GINT_TO_POINTER (slice->id), slice);

  return slice;
}

GlickSlice *
glick_slice_ref (GlickSlice *slice)
{
  slice->ref_count++;
  return slice;
}

void
glick_slice_unref (GlickSlice *slice)
{
  slice->ref_count--;
  if (slice->ref_count == 0)
    {
      g_hash_table_remove (glick_slices_by_id, GINT_TO_POINTER (slice->id));
      close (slice->fd);
      g_free (slice);
    }
}

GlickMount *
glick_mount_new (void)
{
  GlickMount *mount;

  mount = g_new0 (GlickMount, 1);
  mount->ref_count = 1;
  mount->id = next_glick_mount_id++;

  if (mount->id > MAX_MOUNT_ID)
    {
      g_warning ("Out of mount ids");
      g_free (mount);
      return NULL;
    }

  mount->name = g_strdup_printf ("%d", (int)mount->id);

  glick_mounts = g_list_prepend (glick_mounts, mount);
  g_hash_table_insert (glick_mounts_by_id, GINT_TO_POINTER (mount->id), mount);
  g_hash_table_insert (glick_mounts_by_name, mount->name, mount);

  return mount;
}

GlickMount *
glick_mount_ref (GlickMount *mount)
{
  mount->ref_count++;
  return mount;
}

void
glick_mount_unref (GlickMount *mount)
{
  GList *l;

  mount->ref_count--;
  if (mount->ref_count == 0)
    {
      glick_mounts = g_list_remove (glick_mounts, mount);
      g_hash_table_remove (glick_mounts_by_id, GINT_TO_POINTER (mount->id));
      g_hash_table_remove (glick_mounts_by_name, mount->name);

      for (l = mount->slices; l != NULL; l = l->next)
	glick_slice_unref (l->data);

      g_list_free (mount->slices);

      g_free (mount->name);
      g_free (mount);
    }
}

void
glick_mount_add_slice (GlickMount *mount, GlickSlice *slice)
{
  mount->slices = g_list_prepend (mount->slices, slice);
}

GlickMountRef *
glick_mount_ref_new (int fd)
{
  GlickMountRef *ref;

  ref = g_new0 (GlickMountRef, 1);
  ref->socket_fd = fd;

  glick_mount_refs = g_list_prepend (glick_mount_refs, ref);

  return ref;
}

void
glick_mount_ref_free (GlickMountRef *ref)
{
  glick_mount_refs = g_list_remove (glick_mount_refs, ref);

  if (ref->mount)
    glick_mount_unref (ref->mount);

  close (ref->socket_fd);
  g_free (ref);
}

void
glick_mount_ref_handle_request (GlickMountRef *ref,
				GlickMountRequestMsg *request,
				int fd)
{
  GlickMountRequestReply reply;
  GlickSlice *slice;

  memset (&reply, 0, sizeof (reply));

  if (ref->mount != NULL)
    {
      reply.result = 3;
      goto out;
    }

  ref->mount = glick_mount_new ();
  if (ref->mount == NULL)
    {
      reply.result = 4;
      goto out;
    }

  slice = glick_slice_create (fd, 0);
  glick_mount_add_slice (ref->mount, slice);

  reply.result = 0;
  strncpy (reply.name, ref->mount->name, sizeof (reply.name));

 out:
  send (ref->socket_fd, &reply, sizeof (reply), 0);
  close (fd);
}

int
main_loop (struct fuse_session *se)
{
  int res = 0;
  struct fuse_chan *ch = fuse_session_next_chan (se, NULL);
  int fuse_fd = fuse_chan_fd (ch);
  size_t bufsize = fuse_chan_bufsize (ch);
  char *buf = (char *) malloc (bufsize);
  struct pollfd *polls;
  int n_polls, polls_needed, i;
  GlickMountRef *ref;
  GList *l, *next;

  if (!buf)
    {
      fprintf(stderr, "fuse: failed to allocate read buffer\n");
      return -1;
    }

  n_polls = 16;
  polls = g_new (struct pollfd, n_polls);

  while (!fuse_session_exited (se))
    {
      struct fuse_chan *tmpch = ch;

      polls_needed = 2 + g_list_length (glick_mount_refs);
      if (polls_needed > n_polls)
	{
	  n_polls = polls_needed;
	  polls = g_renew (struct pollfd, polls, n_polls);
	}

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

      for (l = glick_mount_refs; l != NULL; l = l->next)
	{
	  ref = l->data;

	  polls[i].fd = ref->socket_fd;
	  polls[i].events = POLLIN;
	  polls[i].revents = 0;
	  i++;
	}

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

      /* Handle these before any new mount refs, as that may change the order of
	 the ref list */
      for (l = glick_mount_refs, i = 2; l != NULL; l = next, i++)
	{
	  ref = l->data;
	  next = l->next;

	  if (polls[i].revents & POLLHUP)
	    {
	      g_print ("socket %d hung up\n", i);
	      glick_mount_ref_free (ref);
	    }
	  else if (polls[i].revents & POLLIN)
	    {
	      int res, passed_fd;
	      GlickMountRequestMsg request;
	      GlickMountRequestReply reply;

	      memset (&reply, 0, sizeof (reply));
	      res = recv_socket_message (ref->socket_fd, (char *)&request, sizeof (request), &passed_fd);
	      if (res != -1)
		{
		  if (passed_fd == -1)
		    {
		      fprintf (stderr, "No fd passed\n");
		      reply.result = 1;
		      send (ref->socket_fd, &reply, sizeof (reply), 0);
		    }
		  else if (res != sizeof (request))
		    {
		      fprintf (stderr, "Invalid glick request size\n");
		      reply.result = 2;
		      close (passed_fd);
		      send (ref->socket_fd, &reply, sizeof (reply), 0);
		    }
		  else
		    {
		      glick_mount_ref_handle_request (ref, &request, passed_fd);
		    }
		}
	    }
	}

      if (polls[1].revents != 0)
	{
	  if (master_socket_ready_pipe != 0)
	    {
	      /* Waiting for master socket to be ready */
	      res = listen (master_socket, 5);
	      if (res == -1)
		perror ("listen");

	      close (master_socket_ready_pipe);
	      master_socket_ready_pipe = 0;
	    }
	  else
	    {
	      int res;
	      res = accept (master_socket, NULL, NULL);

	      if (res == -1)
		perror ("accept");
	      else
		glick_mount_ref_new (res);
	    }
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
  const char *homedir;

  glick_mounts_by_id = g_hash_table_new (g_direct_hash, g_direct_equal);
  glick_mounts_by_name = g_hash_table_new (g_str_hash, g_str_equal);
  glick_slices_by_id = g_hash_table_new (g_direct_hash, g_direct_equal);

  homedir = g_get_home_dir ();
  mountpoint = g_build_filename (homedir, ".glick", NULL);
  mkdir (mountpoint, 0700);

  if ((ch = fuse_mount (mountpoint, NULL)) != NULL)
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
