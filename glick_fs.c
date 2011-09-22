#define FUSE_USE_VERSION 26

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
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
#include "format.h"

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
  uint64_t file_size;
  uint64_t slice_offset; /* File relative */
  uint64_t data_offset; /* File relative */

  char *slice_data;
  uint64_t slice_length;

  GlickSliceHash *hash;
  uint32_t hash_shift; /* 1 << hash_shift == num hash entries */

  char *strings;
  size_t strings_size;

  GlickSliceInode *inodes;
  uint32_t num_inodes;

  GlickSliceDirEntry *dirs;
  uint32_t num_dirs;
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

typedef struct {
  int fd;
  uint64_t start;
  uint64_t end;
} GlickOpenFile;

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

#define ENTRY_CACHE_TIMEOUT_SEC 10
#define ATTR_CACHE_TIMEOUT_SEC 10

static GHashTable *glick_mounts_by_id; /* id -> GlickMount */
static GHashTable *glick_mounts_by_name; /* name -> GlickMount */
static GList *glick_mounts = NULL; /* list of GlickMount */
static GList *glick_mount_refs = NULL; /* list of GlickMountRefs */
static int next_glick_mount_id = 3;

static GList *glick_slices = NULL; /* list of GlickSlice */
static GHashTable *glick_slices_by_id; /* id -> GlickSlice */
static uint32_t next_glick_slice_id = 1;
static unsigned long fuse_generation = 1;

static int master_socket_ready_pipe = 0;
static int socket_created = 0;
static int master_socket;

GlickSliceInode * glick_slice_lookup_path (GlickSlice *slice, const char *path, uint32_t path_hash, uint32_t *inode_num);


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

uint32_t
djb_hash (const void *v)
{
  const signed char *p;
  uint32_t h = 5381;

  for (p = v; *p != '\0'; p++)
    h = (h << 5) + h + *p;

  return h;
}

static int
glick_fs_stat (fuse_ino_t ino, struct stat *stbuf)
{
  gulong id, local;
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

	  mount = g_hash_table_lookup (glick_mounts_by_id, GINT_TO_POINTER (id));
	  if (mount == NULL)
	    return -1;

	  stbuf->st_mode = S_IFDIR | 0755;
	  stbuf->st_nlink = 2;
	  stbuf->st_size = 0;
	}
    }
  else
    {
      GlickSliceInode *inode;

      /* Regular File */
      id = FILE_INODE_GET_SLICE (ino);

      slice = g_hash_table_lookup (glick_slices_by_id, GINT_TO_POINTER (id));
      if (slice == NULL)
	return -1;

      local = FILE_INODE_GET_LOCAL (ino);

      if (local >= slice->num_inodes)
	return -1;

      inode = &slice->inodes[local];
      stbuf->st_nlink = 1;
      stbuf->st_mode = GUINT32_FROM_LE (inode->mode);
      stbuf->st_size = GUINT64_FROM_LE (inode->size);
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
    fuse_reply_attr (req, &stbuf, ATTR_CACHE_TIMEOUT_SEC);
}

static void
glick_fs_lookup (fuse_req_t req, fuse_ino_t parent,
		 const char *name)
{
  struct fuse_entry_param e = { 0 };
  int mount_id;
  int parent_subdir;
  GlickMount *mount;
  char *parent_path, *path;
  uint32_t path_hash;

  g_print ("glick_fs_lookup, parent %d '%s'\n", (int)parent, name);

  e.generation = fuse_generation;
  e.attr_timeout = ATTR_CACHE_TIMEOUT_SEC;
  e.entry_timeout = ENTRY_CACHE_TIMEOUT_SEC;

  if (INODE_IS_FILE (parent) || parent == SOCKET_INODE)
    {
      fuse_reply_err (req, ENOTDIR);
      return;
    }
  else if (parent == ROOT_INODE)
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
      if (mount != NULL)
	{
	  GList *l;

	  /* Handle lookups inside subdirs */

	  if (parent_subdir == 0)
	    parent_path = "";
	  else
	    parent_path = g_hash_table_lookup (mount->inode_to_path, GINT_TO_POINTER (parent_subdir));
	  if (parent_path != NULL)
	    {
	      path = g_strconcat (parent_path, "/", name, NULL);
	      path_hash = djb_hash (path);

	      for (l = mount->slices; l != NULL; l = l->next)
		{
		  GlickSlice *slice = l->data;
		  uint32_t inode_num;
		  GlickSliceInode *inode;

		  inode = glick_slice_lookup_path (slice, path, path_hash, &inode_num);
		  if (inode != NULL)
		    {
		      uint32_t mode = GUINT32_FROM_LE (inode->mode);

		      if (S_ISDIR (mode))
			{
			  uint32_t dir_inode;

			  dir_inode = GPOINTER_TO_UINT (g_hash_table_lookup (mount->path_to_inode, path));
			  if (dir_inode == 0)
			    {
			      dir_inode = mount->next_dir_inode++;

			      /* Transfers ownership of path */
			      g_hash_table_insert (mount->inode_to_path, GUINT_TO_POINTER (dir_inode), path);
			      g_hash_table_insert (mount->path_to_inode, path, GUINT_TO_POINTER (dir_inode));
			    }
			  else
			    g_free (path);

			  e.ino = DIRECTORY_INODE(mount->id, dir_inode);
			  e.attr.st_mode = S_IFDIR | 0755;
			  e.attr.st_ino = e.ino;
			  e.attr.st_nlink = 2;
			  e.attr.st_size = 0;
			  glick_fs_stat (e.ino, &e.attr);
			  g_print ("replying with dir inode\n");
			  fuse_reply_entry (req, &e);
			  return;
			}
		      else
			{
			  e.ino = FILE_INODE(slice->id, inode_num);
			  e.attr.st_mode = mode;
			  e.attr.st_ino = e.ino;
			  e.attr.st_nlink = 1;
			  e.attr.st_size = GUINT64_FROM_LE (inode->size);
			  glick_fs_stat (e.ino, &e.attr);
			  g_print ("replying with file inode\n");
			  fuse_reply_entry (req, &e);

			  g_free (path);
			  return;
			}
		    }
		}
	      g_free (path);
	    }
	}
    }

  e.ino = 0;
  fuse_reply_entry (req, &e);
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
      char *dir_path;

      mount = g_hash_table_lookup (glick_mounts_by_id, GINT_TO_POINTER (id));
      if (mount == NULL)
	{
	  fuse_reply_err (req, ENOENT);
	  goto out;
	}

      if (subdir == 0)
	dir_path = "/";
      else
	dir_path = g_hash_table_lookup (mount->inode_to_path, GINT_TO_POINTER (subdir));

      if (dir_path != NULL)
	{
	  uint32_t dir_path_hash = djb_hash (dir_path);

	  // TODO: Wrong...
	  dirbuf_add (req, &b, "..", ROOT_INODE);

	  for (l = mount->slices; l != NULL; l = l->next)
	    {
	      GlickSlice *slice = l->data;
	      uint64_t dirent, last_dirent, i;
	      uint32_t inode_num;
	      GlickSliceInode *inode;

	      inode = glick_slice_lookup_path (slice, dir_path, dir_path_hash, &inode_num);
	      if (inode != NULL && S_ISDIR (GUINT32_FROM_LE (inode->mode))) {
		dirent = GUINT64_FROM_LE (inode->offset);
		last_dirent = dirent + GUINT64_FROM_LE (inode->size);
		dirent = MIN (dirent, slice->num_dirs);
		last_dirent = MIN (last_dirent, slice->num_dirs);
		for (i = dirent; i < last_dirent; i++) {
		  uint16_t entry_inode = GUINT16_FROM_LE (slice->dirs[i].inode);
		  if (entry_inode < slice->num_inodes) {
		    uint32_t name = GUINT32_FROM_LE (slice->inodes[entry_inode].name);
		    /* TODO: Check for null termination */
		    if (name < slice->strings_size)
		      dirbuf_add (req, &b, slice->strings + name, FILE_INODE(slice->id, entry_inode));
		  }
		}
	      }

	    }

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
  fi->fh = 0;

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
      if (local < slice->num_inodes)
	{
	  GlickSliceInode *inodep;
	  GlickOpenFile *open;

	  inodep = &slice->inodes[local];
	  if (S_ISREG (GUINT32_FROM_LE (inodep->mode))) {
	    open = g_new0 (GlickOpenFile, 1);
	    open->fd = slice->fd;
	    open->start = slice->data_offset + GUINT64_FROM_LE (inodep->offset);
	    open->end = open->start + GUINT64_FROM_LE (inodep->size);
	    fi->fh = (uint64_t)open;
	    fuse_reply_open (req, fi);
	  }
	}
      else
	fuse_reply_err (req, EACCES);
    }
}

static void
glick_fs_release (fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
  GlickOpenFile *open = (GlickOpenFile *) fi->fh;

  g_free (open);
  fuse_reply_err (req, 0);
}

static void
glick_fs_read (fuse_req_t req, fuse_ino_t ino, size_t size,
	       off_t off, struct fuse_file_info *fi)
{
  char *buf;
  ssize_t res;
  GlickOpenFile *open;
  uint64_t start, end;

  g_print ("glick_fs_read\n");

  open = (GlickOpenFile *)fi->fh;
  start = open->start + off;
  end = start + size;
  start = MIN (start, open->end);
  end = MIN (end, open->end);

  size = end - start;
  buf = malloc (size);
  res = pread (open->fd, buf, size, start);

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

  e.generation = fuse_generation;

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
  .release	= glick_fs_release,
  .read		= glick_fs_read,
  .mknod	= glick_fs_mknod,
};

void *
verify_header_block (char *data,
		     uint32_t slice_size,
		     uint32_t block_offset,
		     uint32_t block_element_size,
		     uint32_t block_n_elements)
{
  /* Avoid overflow in size calculation by doing it in 64bit */
  uint64_t block_size = (uint64_t)block_element_size * (uint64_t)block_n_elements;

  /* Don't wrap */
  if ((uint64_t)block_offset + block_size < (uint64_t)block_offset)
    return NULL;

  /* Make sure block fits in slice */
  if ((uint64_t)block_offset + block_size >= (uint64_t)slice_size)
    return NULL;

  return data + block_offset;
}

/* Looks up or creates a new slice */
GlickSlice *
glick_slice_create (int fd,
		    uint64_t slice_offset)
{
  GlickSlice *slice;
  struct stat statbuf;
  char *data;
  uint32_t slice_length;
  uint64_t data_offset, data_size;
  GlickSliceRoot *root;

  if (fstat (fd, &statbuf) != 0)
    return NULL;

  if (slice_offset + sizeof (GlickSliceRoot) >= statbuf.st_size)
    return NULL;

  data = mmap (NULL, sizeof (GlickSliceRoot), PROT_READ,
	       MAP_PRIVATE, fd, slice_offset);
  if (data == NULL)
    return NULL;

  root = (GlickSliceRoot *)data;

  slice_length = GUINT32_FROM_LE (root->slice_length);

  munmap (data, sizeof (GlickSliceRoot));

  /* Ensure that the slice fits in the file */
  if (slice_offset >= statbuf.st_size ||
      slice_length > statbuf.st_size ||
      slice_offset > statbuf.st_size - slice_length)
    return NULL;

  /* slice_length is uint32, so this can't wrap size_t */
  data = mmap (NULL, slice_length, PROT_READ,
	       MAP_PRIVATE, fd, slice_offset);
  if (data == NULL)
    return NULL;

  root = (GlickSliceRoot *)data;

  /* Make sure size didn't randomly change under us after remap */
  if (GUINT32_FROM_LE (root->slice_length) != slice_length) {
    return NULL;
  }

  slice = g_new0 (GlickSlice, 1);
  slice->ref_count = 1;
  slice->id = next_glick_slice_id++;
  slice->file_size = statbuf.st_size;

  slice->slice_offset = slice_offset;
  slice->slice_data = data;
  slice->slice_length = slice_length;

  if (slice->id > MAX_SLICE_ID)
    {
      g_warning ("Out of slice ids\n");
      goto error;
    }

  data_size = GUINT64_FROM_LE (root->data_size);
  data_offset = GUINT32_FROM_LE (root->data_offset);

  // Convert to file-relative and ensure no wrap
  if (slice_offset + data_offset < slice_offset)
    goto error;
  data_offset = slice_offset + data_offset;

  /* Ensure data is in file */
  if (data_offset >= statbuf.st_size ||
      data_size > statbuf.st_size ||
      data_offset > statbuf.st_size - data_size)
    goto error;

  slice->data_offset = data_offset;

  slice->hash_shift = GUINT32_FROM_LE(root->hash_shift);;
  if (slice->hash_shift >= 32)
    goto error;
  slice->hash = verify_header_block (data, slice_length,
				     GUINT32_FROM_LE(root->hash_offset),
				     1U << slice->hash_shift , sizeof (GlickSliceHash));
  if (slice->hash == NULL)
    goto error;

  slice->num_inodes = GUINT32_FROM_LE(root->num_inodes);
  slice->inodes = verify_header_block (data, slice_length,
				       GUINT32_FROM_LE(root->inodes_offset),
				       slice->num_inodes, sizeof (GlickSliceInode));
  if (slice->inodes == NULL)
    goto error;

  slice->num_dirs = GUINT32_FROM_LE(root->num_dirs);
  slice->dirs = verify_header_block (data, slice_length,
				     GUINT32_FROM_LE(root->dirs_offset),
				     slice->num_dirs, sizeof (GlickSliceDirEntry));
  if (slice->dirs == NULL)
    goto error;

  slice->strings_size = GUINT32_FROM_LE(root->strings_size);
  slice->strings = verify_header_block (data, slice_length,
					GUINT32_FROM_LE(root->strings_offset),
					slice->strings_size, 1);
  if (slice->strings == NULL)
    goto error;

  slice->fd = dup (fd);

  glick_slices = g_list_prepend (glick_slices, slice);
  g_hash_table_insert (glick_slices_by_id, GINT_TO_POINTER (slice->id), slice);

  return slice;

 error:
  munmap (data, slice_length);
  g_free (slice);
  return NULL;
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
      munmap (slice->slice_data, slice->slice_length);
      close (slice->fd);
      g_free (slice);
    }
}

gboolean
glick_slice_string_equal (GlickSlice *slice, uint32_t str_offset, const char *other, const char *other_end)
{
  const char *str, *strings_end;

  if (other_end == NULL)
    other_end = other + strlen (other);

  strings_end = slice->strings + slice->strings_size;
  str = slice->strings + str_offset;
  while (other < other_end &&
	 str < strings_end && *str != 0) {
    if (*other != *str)
      return FALSE;
    other++;
    str++;
  }
  return (other == other_end &&
	  (str == strings_end || *str == 0));
}

gboolean
glick_slice_inode_has_path (GlickSlice *slice, GlickSliceInode *inodep, const char *path, const char *path_end)
{
  const char *last_slash;
  const char *path_component;
  uint16_t parent_inode;

  /* Empty paths not allowed */
  if (path == path_end)
    return FALSE;

  last_slash = path_end - 1;
  while (last_slash > path && *last_slash != '/')
    last_slash--;

  if (*last_slash != '/')
    return FALSE; /* No slash, can't match anything */

  if (last_slash + 1 == path_end)
    path_component = last_slash;
  else
    path_component = last_slash + 1;

  if (!glick_slice_string_equal (slice, GUINT32_FROM_LE (inodep->name), path_component, path_end))
    return FALSE;

  parent_inode = GUINT16_FROM_LE (inodep->parent_inode);
  if (parent_inode >= slice->num_inodes)
    return FALSE;

  if (last_slash == path)
    return parent_inode == 0;

  return glick_slice_inode_has_path (slice, &slice->inodes[parent_inode], path, last_slash);
}

GlickSliceInode *
glick_slice_lookup_path (GlickSlice *slice, const char *path, uint32_t path_hash, uint32_t *inode_num)
{
  uint32_t hash_bin;
  uint32_t hash_mask;
  uint32_t inode;
  GlickSliceInode *inodep;
  int step;

  hash_mask = (1U << slice->hash_shift) - 1;
  hash_bin = path_hash & hash_mask;

  step = 1;
  while (slice->hash[hash_bin].inode != INVALID_INODE) {
    inode = GUINT16_FROM_LE (slice->hash[hash_bin].inode);
    if (inode < slice->num_inodes) {
      inodep = &slice->inodes[inode];
      if (GUINT32_FROM_LE (inodep->path_hash) == path_hash &&
	  glick_slice_inode_has_path (slice, inodep, path, path + strlen (path))) {
	*inode_num = inode;
	return inodep;
      }
    }

    hash_bin = (hash_bin + step) & hash_mask;
    step++;
  }

  return NULL;
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

  mount->inode_to_path = g_hash_table_new (g_direct_hash, g_direct_equal);
  mount->path_to_inode = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  mount->next_dir_inode = 1;

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
