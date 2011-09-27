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

/* TODO:
 * Add support for mtime/ctime/atime
 * Add bloom table for hash lookups
 * Add bundle support (more than one slice)
 * Support sha1-based merging
 * Track installed bundles
 * Convert to use GMainLoop
 * Add public mount and merge into rest
 * Add installed bundles symlinks
 * Track kernel refs to inodes (lookup/forget)
 * Free transient dirs and invalidate inodes when slices are removed
 * Invalidate entries when slices are added
 * Support renames of transient files
 * Support access()
 * Support triggers
 */

/* Inodes:
   32 bits

   Invalid:
   00000000000000000000000000000000

   Root:
   00000000000000000000000000000001

   Socket:
   00000000000000000000000000000010

   Toplevel Directory:
		   +- 16bit glick mount id (>=3)
		   v
   0000000000000000yyyyyyyyyyyyyyyy

   GlickMount transient file:

    +- 15bit transient id per glick mount (!= 0)
    |              +- 16bit glick mount id (>=3)
    v              v
   0xxxxxxxxxxxxxxxyyyyyyyyyyyyyyyy

   Slice File:

    +- 15bit slice id
    |              +- 16bit fixed inode in slice
    v              v
   1xxxxxxxxxxxxxxxyyyyyyyyyyyyyyyy

*/

typedef struct {
  int ref_count;
  guint32 id;
  int fd;
  guint64 file_size;
  guint64 slice_offset; /* File relative */
  guint64 data_offset; /* File relative */

  char *slice_data;
  guint64 slice_length;

  GlickSliceHash *hash;
  guint32 hash_shift; /* 1 << hash_shift == num hash entries */

  char *strings;
  gsize strings_size;

  GlickSliceInode *inodes;
  guint32 num_inodes;

  GlickSliceDirEntry *dirs;
  guint32 num_dirs;
} GlickSlice;

typedef struct {
  char *name;
  int ref_count;
  unsigned long id;

  GHashTable *inode_to_file;
  GHashTable *path_to_file;
  int next_mount_file_inode;

  GList *slices;
} GlickMount;

typedef struct GlickMountTransientFile GlickMountTransientFile;

struct GlickMountTransientFile {
  GlickMount *mount;
  gboolean owned; /* TRUE => exists even if not referenced by slice */
  mode_t mode;
  char *path;
  char *name;
  guint16 inode;
  GlickMountTransientFile *parent;
  guint file_ref_count; /* This keeps directories alive if there is a owned file/dir in it */
  char *data;
  int fd;

  GList *children;
};

typedef struct {
  int socket_fd;
  GlickMount *mount;
}  GlickMountRef;

typedef struct {
  int fd;
  guint64 start;
  gint64 end;
  int flags;
} GlickOpenFile;

#define ROOT_INODE 1
#define SOCKET_INODE 2
#define SOCKET_NAME "socket"

#define SLICE_FILE_INODE_MASK 0x80000000
#define INODE_IS_SLICE_FILE(ino) (((ino) & SLICE_FILE_INODE_MASK) != 0)
#define TRANSIENT_FILE_INODE_MOUNT_MASK 0x0000FFFF
#define TRANSIENT_FILE_INODE_TRANSIENT_MASK 0x7FFF0000
#define TRANSIENT_FILE_INODE_TRANSIENT_SHIFT 16
#define TRANSIENT_FILE_INODE_GET_MOUNT(x) ((x) & TRANSIENT_FILE_INODE_MOUNT_MASK)
#define TRANSIENT_FILE_INODE_GET_TRANSIENT(x) (((x) & TRANSIENT_FILE_INODE_TRANSIENT_MASK) >> TRANSIENT_FILE_INODE_TRANSIENT_SHIFT)
#define TRANSIENT_FILE_INODE(id, file) ((id) | ((file) << TRANSIENT_FILE_INODE_TRANSIENT_SHIFT))
#define TRANSIENT_FILE_INODE_FROM_MOUNT(id) TRANSIENT_FILE_INODE((id), 0)
#define SLICE_FILE_INODE_SLICE_SHIFT 16
#define SLICE_FILE_INODE_LOCAL_MASK 0x0000FFFF
#define SLICE_FILE_INODE_SLICE_MASK 0x7FFF0000
#define SLICE_FILE_INODE(slice_id, local_inode) (SLICE_FILE_INODE_MASK | ((slice_id) << SLICE_FILE_INODE_SLICE_SHIFT) | (local_inode))
#define SLICE_FILE_INODE_GET_LOCAL(x) ((x) & SLICE_FILE_INODE_LOCAL_MASK)
#define SLICE_FILE_INODE_GET_SLICE(x) (((x) & SLICE_FILE_INODE_SLICE_MASK) >> SLICE_FILE_INODE_SLICE_SHIFT)
#define MAX_SLICE_ID 0x8fff
#define MAX_TRANSIENT_ID 0x8fff
#define MAX_MOUNT_ID 0xffff

#define ENTRY_CACHE_TIMEOUT_SEC 10000
#define ATTR_CACHE_TIMEOUT_SEC 10000

static GHashTable *glick_mounts_by_id; /* id -> GlickMount */
static GHashTable *glick_mounts_by_name; /* name -> GlickMount */
static GList *glick_mounts = NULL; /* list of GlickMount */
static GList *glick_mount_refs = NULL; /* list of GlickMountRefs */
static int next_glick_mount_id = 3;

static GList *glick_slices = NULL; /* list of GlickSlice */
static GHashTable *glick_slices_by_id; /* id -> GlickSlice */
static guint32 next_glick_slice_id = 1;
static unsigned long fuse_generation = 1;

static int master_socket_ready_pipe = 0;
static int socket_created = 0;
static int master_socket;

const char *glick_slice_lookup_string (GlickSlice *slice, size_t offset);
GlickSliceInode * glick_slice_lookup_path (GlickSlice *slice, const char *path, guint32 path_hash, guint32 *inode_num);
GlickSliceInode * glick_mount_lookup_path (GlickMount *mount, const char *path, GlickSlice **slice_out, guint32 *inode_num);
GlickMountTransientFile *glick_mount_transient_file_new (GlickMount *mount, GlickMountTransientFile *parent, const char *path, gboolean owned);
GlickMountTransientFile *glick_mount_transient_file_new_dir (GlickMount *mount, GlickMountTransientFile *parent, char *path, gboolean owned);
GlickMountTransientFile *glick_mount_transient_file_new_file (GlickMount *mount, GlickMountTransientFile *parent, char *path);
void glick_mount_transient_file_stat (GlickMountTransientFile *file, struct stat *statbuf);
void glick_mount_transient_file_unown (GlickMountTransientFile *file);
void glick_mount_transient_file_own (GlickMountTransientFile *file);
void glick_mount_transient_file_free (GlickMountTransientFile *file);

#if 1
#define __debug__(x) g_print x
#else
#define __debug__(x)
#endif

int
recv_socket_message (int socket_fd,
		     char *buffer,
		     gsize buffer_size,
		     int *recieved_fd)
{
  struct msghdr socket_message = { 0 };
  struct iovec io_vector[1];
  struct cmsghdr *control_message = NULL;
  gssize res;
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

guint32
djb_hash (const void *v)
{
  const signed char *p;
  guint32 h = 5381;

  for (p = v; *p != '\0'; p++)
    h = (h << 5) + h + *p;

  return h;
}

static GlickMountTransientFile *
get_transient_file_from_inode (fuse_ino_t ino, GlickMount **mount_out)
{
    gulong id, transient;
    GlickMount *mount;
    GlickMountTransientFile *file;

    id = TRANSIENT_FILE_INODE_GET_MOUNT (ino);
    mount = g_hash_table_lookup (glick_mounts_by_id, GINT_TO_POINTER (id));
    if (mount == NULL)
      return NULL;

    transient = TRANSIENT_FILE_INODE_GET_TRANSIENT(ino);
    file = g_hash_table_lookup (mount->inode_to_file, GINT_TO_POINTER (transient));
    if (file == NULL)
      return NULL;

    if (mount_out)
      *mount_out = mount;
    return file;
}

static int
glick_fs_stat (fuse_ino_t ino, struct stat *stbuf)
{
  gulong id, local;
  GlickSlice *slice;
  GlickMountTransientFile *file;

  stbuf->st_ino = ino;

  if (!INODE_IS_SLICE_FILE (ino))
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
	  file = get_transient_file_from_inode (ino, NULL);
	  glick_mount_transient_file_stat (file, stbuf);
	}
    }
  else
    {
      GlickSliceInode *inode;

      /* Regular File */
      id = SLICE_FILE_INODE_GET_SLICE (ino);

      slice = g_hash_table_lookup (glick_slices_by_id, GINT_TO_POINTER (id));
      if (slice == NULL)
	return -1;

      local = SLICE_FILE_INODE_GET_LOCAL (ino);

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

  __debug__ (("glick_fs_getattr %x\n", (int)ino));
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
  char *path;

  __debug__ (("glick_fs_lookup, parent %x '%s'\n", (int)parent, name));

  e.generation = fuse_generation;
  e.attr_timeout = ATTR_CACHE_TIMEOUT_SEC;
  e.entry_timeout = ENTRY_CACHE_TIMEOUT_SEC;

  if (INODE_IS_SLICE_FILE (parent) || parent == SOCKET_INODE)
    {
      __debug__ (("replying with NOTDIR\n"));
      fuse_reply_err (req, ENOTDIR);
      return;
    }
  else if (parent == ROOT_INODE)
    {
      if (socket_created &&
	  strcmp (SOCKET_NAME, name) == 0)
	{
	  e.ino = SOCKET_INODE;
	  e.attr.st_mode = S_IFSOCK | 0777;
	  e.attr.st_nlink = 1;
	  e.attr.st_size = 0;
	  __debug__ (("replying with socket\n"));
	  fuse_reply_entry (req, &e);
	  return;
	}
      mount = g_hash_table_lookup (glick_mounts_by_name, name);
      if (mount)
	{
	  e.ino = TRANSIENT_FILE_INODE_FROM_MOUNT (mount->id);
	  e.attr.st_mode = S_IFDIR | 0755;
	  e.attr.st_nlink = 2;
	  e.attr.st_size = 0;
	  __debug__ (("replying with mount dir\n"));
	  fuse_reply_entry (req, &e);
	  return;
	}
    }
  else
    {
      mount_id = TRANSIENT_FILE_INODE_GET_MOUNT(parent);
      parent_subdir = TRANSIENT_FILE_INODE_GET_TRANSIENT(parent);

      mount = (GlickMount *)g_hash_table_lookup (glick_mounts_by_id, GINT_TO_POINTER (mount_id));
      if (mount != NULL)
	{
	  GlickMountTransientFile *parent_file, *file;
	  GlickSlice *slice;
	  guint32 inode_num;
	  GlickSliceInode *inode;

	  /* Handle lookups inside subdirs */

	  parent_file = g_hash_table_lookup (mount->inode_to_file, GINT_TO_POINTER (parent_subdir));
	  if (parent_file != NULL)
	    {
	      if (!S_ISDIR (parent_file->mode))
		{
		  __debug__ (("replying with NOTDIR\n"));
		  fuse_reply_err (req, ENOTDIR);
		  return;
		}

	      path = g_build_filename (parent_file->path, name, NULL);
	      inode = glick_mount_lookup_path (mount, path, &slice, &inode_num);
	      if (inode != NULL)
		{
		  guint32 mode = GUINT32_FROM_LE (inode->mode);

		  if (S_ISDIR (mode))
		    {
		      file = g_hash_table_lookup (mount->path_to_file, path);
		      if (file == 0)
			file = glick_mount_transient_file_new_dir (mount, parent_file, path, FALSE);
		      g_free (path);

		      glick_mount_transient_file_stat (file, &e.attr);
		      e.ino = e.attr.st_ino;
		      __debug__ (("replying with transient inode\n"));
		      fuse_reply_entry (req, &e);
		      return;
		    }
		  else
		    {
		      e.ino = SLICE_FILE_INODE(slice->id, inode_num);
		      e.attr.st_mode = mode;
		      e.attr.st_ino = e.ino;
		      e.attr.st_nlink = 1;
		      e.attr.st_size = GUINT64_FROM_LE (inode->size);
		      __debug__ (("replying with file inode\n"));
		      fuse_reply_entry (req, &e);

		      g_free (path);
		      return;
		    }
		}

	      file = g_hash_table_lookup (mount->path_to_file, path);
	      if (file != NULL && (file->file_ref_count > 0 || file->owned))
		{
		  glick_mount_transient_file_stat (file, &e.attr);
		  e.ino = e.attr.st_ino;
		  __debug__ (("replying with transient (reffed) inode\n"));
		  fuse_reply_entry (req, &e);
		  g_free (path);
		  return;
		}

	      g_free (path);
	    }
	}
    }

  __debug__ (("replying with NOENT\n"));
  e.ino = 0;
  fuse_reply_entry (req, &e);
}

struct dirbuf {
  char *p;
  gsize size;
};

static struct dirbuf *
dirbuf_new (void)
{
  return g_new0 (struct dirbuf, 1);
}

static void
dirbuf_add (fuse_req_t req, struct dirbuf *b, const char *name,
	    fuse_ino_t ino)
{
  struct stat stbuf;
  gsize oldsize = b->size;

  b->size += fuse_add_direntry (req, NULL, 0, name, NULL, 0);
  b->p = (char *) g_realloc (b->p, b->size);
  memset (&stbuf, 0, sizeof (stbuf));
  stbuf.st_ino = ino;
  fuse_add_direntry (req, b->p + oldsize, b->size - oldsize, name, &stbuf,
		     b->size);
}

static void
dirbuf_free (struct dirbuf *b)
{
  if (b)
    {
      g_free (b->p);
      g_free (b);
    }
}


#define min(x, y) ((x) < (y) ? (x) : (y))

static int
reply_buf_limited (fuse_req_t req, const char *buf, gsize bufsize,
		   off_t off, gsize maxsize)
{
  if (off < bufsize)
    return fuse_reply_buf (req, buf + off,
			   min (bufsize - off, maxsize));
  else
    return fuse_reply_buf (req, NULL, 0);
}

static void
glick_fs_opendir (fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
  struct dirbuf *b;
  GList *l;
  GHashTable *names_used;

  __debug__ (("glick_fs_opendir %x\n", (int)ino));
  fi->fh = 0;

  if (INODE_IS_SLICE_FILE (ino) || ino == SOCKET_INODE)
    {
      fuse_reply_err (req, ENOTDIR);
      return;
    }

  b = dirbuf_new ();

  dirbuf_add (req, b, ".", ino);

  if (ino == ROOT_INODE)
    {
      dirbuf_add (req, b, "..", ROOT_INODE);
      if (socket_created)
	dirbuf_add (req, b, SOCKET_NAME, SOCKET_INODE);
      for (l = glick_mounts; l != NULL; l = l->next)
	{
	  GlickMount *mount = l->data;

	  dirbuf_add (req, b, mount->name,
		      TRANSIENT_FILE_INODE_FROM_MOUNT(mount->id));
	}
    }
  else
    {
      guint32 dir_path_hash;
      GlickMount *mount;
      GlickMountTransientFile *dir;

      names_used = g_hash_table_new (g_direct_hash, g_direct_equal);

      dir = get_transient_file_from_inode (ino, &mount);
      if (dir == NULL)
	{
	  fuse_reply_err (req, ENOENT);
	  goto out;
	}
      if (!S_ISDIR (dir->mode))
	{
	  fuse_reply_err (req, ENOTDIR);
	  goto out;
	}

      dir_path_hash = djb_hash (dir->path);

      // TODO: Wrong...
      dirbuf_add (req, b, "..", ROOT_INODE);

      for (l = mount->slices; l != NULL; l = l->next)
	{
	  GlickSlice *slice = l->data;
	  guint64 dirent, last_dirent, i;
	  guint32 inode_num;
	  GlickSliceInode *inode;

	  inode = glick_slice_lookup_path (slice, dir->path, dir_path_hash, &inode_num);
	  if (inode != NULL && S_ISDIR (GUINT32_FROM_LE (inode->mode)))
	    {
	      dirent = GUINT64_FROM_LE (inode->offset);
	      last_dirent = dirent + GUINT64_FROM_LE (inode->size);
	      dirent = MIN (dirent, slice->num_dirs);
	      last_dirent = MIN (last_dirent, slice->num_dirs);
	      for (i = dirent; i < last_dirent; i++)
		{
		  guint16 entry_inode = GUINT16_FROM_LE (slice->dirs[i].inode);
		  if (entry_inode < slice->num_inodes)
		    {
		      const char *name = glick_slice_lookup_string (slice, GUINT32_FROM_LE (slice->inodes[entry_inode].name));
		      if (name != NULL && g_hash_table_lookup (names_used, name) == NULL)
			{
			  g_hash_table_insert (names_used, (char *)name, (char *)name);
			  dirbuf_add (req, b, name, SLICE_FILE_INODE(slice->id, entry_inode));
			}
		    }
		}
	    }
	}

      for (l = dir->children; l != NULL; l = l->next)
	{
	  GlickMountTransientFile *child = l->data;

	  if ((child->file_ref_count > 0 || child->owned) &&
	      g_hash_table_lookup (names_used, child->name) == NULL)
	    {
	      g_hash_table_insert (names_used, (char *)child->name, (char *)child->name);
	      dirbuf_add (req, b, child->name, TRANSIENT_FILE_INODE(mount->id, child->inode));
	    }
	}

      g_hash_table_destroy (names_used);
    }

  fi->fh = (guint64)b;
  if (fuse_reply_open (req, fi) == -ENOENT)
    goto out;
  return;

 out:
  dirbuf_free (b);
}

static void
glick_fs_readdir (fuse_req_t req, fuse_ino_t ino, gsize size,
		  off_t off, struct fuse_file_info *fi)
{
  struct dirbuf *b = (struct dirbuf *)fi->fh;
  __debug__ (("glick_fs_readdir %x o=%d s=%d\n", (int)ino, (int)off, (int)size));
  reply_buf_limited (req, b->p, b->size, off, size);
}

static void
glick_fs_releasedir (fuse_req_t req, fuse_ino_t ino,
		     struct fuse_file_info *fi)
{
  struct dirbuf *b = (struct dirbuf *)fi->fh;
  __debug__ (("glick_fs_releasedir %x\n", (int)ino));
  dirbuf_free (b);
  fuse_reply_err (req, 0);
}

static void
glick_fs_open (fuse_req_t req, fuse_ino_t ino,
	       struct fuse_file_info *fi)
{
  GlickSlice *slice;
  int id, local;
  GlickMountTransientFile *file;
  GlickOpenFile *open;

  fi->keep_cache = 1;
  fi->fh = 0;

  __debug__ (("glick_fs_open %x\n", (int)ino));

  if (!INODE_IS_SLICE_FILE (ino))
    {
      file = get_transient_file_from_inode (ino, NULL);
      if (file == NULL ||
	  file->fd == -1)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}

      open = g_new0 (GlickOpenFile, 1);
      open->start = 0;
      open->end = -1;
      open->flags = fi->flags;
      open->fd = file->fd;
      fi->fh = (guint64)open;
      fuse_reply_open (req, fi);
    }
  else
    {
      if ((fi->flags & 3) != O_RDONLY)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}

      id = SLICE_FILE_INODE_GET_SLICE (ino);

      slice = g_hash_table_lookup (glick_slices_by_id, GINT_TO_POINTER (id));
      if (slice == NULL)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}

      local = SLICE_FILE_INODE_GET_LOCAL (ino);
      if (local < slice->num_inodes)
	{
	  GlickSliceInode *inodep;

	  inodep = &slice->inodes[local];
	  if (S_ISREG (GUINT32_FROM_LE (inodep->mode)))
	    {
	      open = g_new0 (GlickOpenFile, 1);
	      open->fd = slice->fd;
	      open->start = slice->data_offset + GUINT64_FROM_LE (inodep->offset);
	      open->end = open->start + GUINT64_FROM_LE (inodep->size);
	      open->flags = fi->flags;
	      fi->fh = (guint64)open;
	      fuse_reply_open (req, fi);
	    }
	  else
	    fuse_reply_err (req, EISDIR);
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

  __debug__ (("glick_fs_release\n"));

  g_free (open);
  fuse_reply_err (req, 0);
}

static void
glick_fs_read (fuse_req_t req, fuse_ino_t ino, gsize size,
	       off_t off, struct fuse_file_info *fi)
{
  char *buf;
  gssize res;
  GlickOpenFile *open;
  guint64 start, end;

  __debug__ (("glick_fs_read\n"));

  open = (GlickOpenFile *)fi->fh;

  if (open->flags & O_WRONLY)
    {
      fuse_reply_err (req, EBADF);
      return;
    }

  start = open->start + off;

  if (open->end != -1)
    {
      end = start + size;
      start = MIN (start, open->end);
      end = MIN (end, open->end);
      size = end - start;
    }

  buf = malloc (size);
  res = pread (open->fd, buf, size, start);
  if (res >= 0)
    fuse_reply_buf (req, buf, res);
  else
    fuse_reply_err (req, errno);
  free (buf);
}

static void
glick_fs_setattr (fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		  int to_set, struct fuse_file_info *fi)
{
  GlickMountTransientFile *file;
  struct stat res_stat;
  int res;

  __debug__ (("glick_fs_setattr\n"));

  if (INODE_IS_SLICE_FILE (ino))
    {
      __debug__ (("replying with EACCESS\n"));
      fuse_reply_err (req, EACCES);
      return;
    }

  file = get_transient_file_from_inode (ino, NULL);
  if (file == NULL ||
      file->fd == -1)
    {
      fuse_reply_err (req, EACCES);
      return;
    }

  if (to_set & FUSE_SET_ATTR_SIZE)
    {
      res = ftruncate (file->fd, attr->st_size);
      if (res != 0)
	{
	  int errsv = errno;
	  __debug__ (("replying with %d\n", errsv));
	  fuse_reply_err (req, errsv);
	  return;
	}
    }
  if (to_set &
      (FUSE_SET_ATTR_MODE |
       FUSE_SET_ATTR_UID |
       FUSE_SET_ATTR_GID |
       FUSE_SET_ATTR_ATIME |
       FUSE_SET_ATTR_MTIME |
       FUSE_SET_ATTR_ATIME_NOW |
       FUSE_SET_ATTR_MTIME_NOW))
    {
      __debug__ (("replying with ENOSYS\n"));
      fuse_reply_err (req, ENOSYS);
      return;
    }

  glick_mount_transient_file_stat (file, &res_stat);
  __debug__ (("replying with access\n"));
  fuse_reply_attr (req, &res_stat, ATTR_CACHE_TIMEOUT_SEC);
}


static void
glick_fs_write (fuse_req_t req, fuse_ino_t ino, const char *buf,
		size_t size, off_t off, struct fuse_file_info *fi)
{
  gssize res;
  GlickOpenFile *open;

  __debug__ (("glick_fs_write\n"));

  open = (GlickOpenFile *)fi->fh;

  if (open->flags & O_RDONLY)
    {
      fuse_reply_err (req, EBADF);
      return;
    }

  /* This assumes open->start is 0 and open->end == -1, which
     should be true as these are only used for readonly files */

  res = pwrite (open->fd, buf, size, off);
  if (res >= 0)
    fuse_reply_write (req, res);
  else
    fuse_reply_err (req, errno);
}

static GlickMountTransientFile *
find_parent_dir_for_path_op (fuse_req_t req, fuse_ino_t parent, GlickMount **mount_out)
{
  GlickMountTransientFile *dir;

  /* All non-root directores are transient files */
  if (INODE_IS_SLICE_FILE (parent) || parent == SOCKET_INODE)
    {
      fuse_reply_err (req, ENOTDIR);
      return NULL;
    }

  /* Can't modify files in the root dir, only in mount dirs */
  if (parent == ROOT_INODE)
    {
      fuse_reply_err (req, EACCES);
      return NULL;
    }


  dir = get_transient_file_from_inode (parent, mount_out);
  if (dir == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return NULL;
    }

  if (!S_ISDIR (dir->mode))
    {
      fuse_reply_err (req, ENOTDIR);
      return NULL;
    }

  return dir;
}

static char *
ensure_no_entry_for_child_op (fuse_req_t req, GlickMount *mount, GlickMountTransientFile *dir, const char *name)
{
  GlickMountTransientFile *file;
  char *path;

  path = g_build_filename (dir->path, name, NULL);
  if (glick_mount_lookup_path (mount, path, NULL, NULL) != NULL)
    {
      fuse_reply_err (req, EEXIST);
      g_free (path);
      return NULL;
    }

  file = g_hash_table_lookup (mount->path_to_file, path);
  if (file != NULL && (file->file_ref_count > 0 || file->owned))
    {
      fuse_reply_err (req, EEXIST);
      g_free (path);
      return NULL;
    }

  if (file != NULL)
    {
      g_warning ("Unowned transient file not in slices. This shouldn't happen.\n");
      fuse_reply_err (req, EEXIST);
      g_free (path);
      return NULL;
    }

  return path;
}

static void
glick_fs_symlink (fuse_req_t req, const char *link, fuse_ino_t parent,
		  const char *name)
{
  struct fuse_entry_param e = {0};
  GlickMount *mount;
  GlickMountTransientFile *dir, *file;
  char *path;

  __debug__ (("glick_fs_symlink %x %s %s\n", (int)parent, name, link));

  dir = find_parent_dir_for_path_op (req, parent, &mount);
  if (dir == NULL)
    return;

  path = ensure_no_entry_for_child_op (req, mount, dir, name);
  if (path == NULL)
    return;

  file = glick_mount_transient_file_new (mount, dir, path, TRUE);
  file->mode = S_IFLNK | 0755;
  file->data = g_strdup (link);

  g_free (path);

  glick_mount_transient_file_stat (file, &e.attr);
  e.ino = e.attr.st_ino;
  e.generation = fuse_generation;
  e.attr_timeout = 1.0;
  e.entry_timeout = 1.0;

  fuse_reply_entry (req, &e);
}

static void
glick_fs_readlink (fuse_req_t req, fuse_ino_t ino)
{
  GlickSlice *slice;
  int id, local;
  GlickMountTransientFile *file;

  __debug__ (("glick_fs_readlink %x\n", (int)ino));

  if (!INODE_IS_SLICE_FILE (ino))
    {
      id = TRANSIENT_FILE_INODE_GET_MOUNT (ino);

      file = get_transient_file_from_inode (ino, NULL);
      if (file == NULL)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}

      if (!S_ISLNK (file->mode) ||
	  file->data == NULL)
	{
	  fuse_reply_err (req, EINVAL);
	  return;
	}

      fuse_reply_readlink (req, file->data);
    }
  else
    {
      id = SLICE_FILE_INODE_GET_SLICE (ino);

      slice = g_hash_table_lookup (glick_slices_by_id, GINT_TO_POINTER (id));
      if (slice == NULL)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}

      local = SLICE_FILE_INODE_GET_LOCAL (ino);
      if (local < slice->num_inodes)
	{
	  GlickSliceInode *inodep;

	  inodep = &slice->inodes[local];
	  if (S_ISLNK (GUINT32_FROM_LE (inodep->mode)))
	    {
	      const char *lnk = glick_slice_lookup_string (slice, GUINT64_FROM_LE (inodep->offset));
	      if (lnk != NULL)
		fuse_reply_readlink (req, lnk);
	      else
		fuse_reply_err (req, EACCES);
	    }
	  else
	    fuse_reply_err (req, EINVAL);
	}
      else
	fuse_reply_err (req, EACCES);
    }
}

static void
glick_fs_mkdir (fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode)
{
  struct fuse_entry_param e = {0};
  GlickMount *mount;
  GlickMountTransientFile *dir, *file;
  char *path;

  __debug__ (("glick_fs_mkdir %x %s %x\n", (int)parent, name, mode));

  dir = find_parent_dir_for_path_op (req, parent, &mount);
  if (dir == NULL)
    return;

  path = ensure_no_entry_for_child_op (req, mount, dir, name);
  if (path == NULL)
    return;

  file = glick_mount_transient_file_new_dir (mount, dir, path, TRUE);
  g_free (path);

  glick_mount_transient_file_stat (file, &e.attr);
  e.ino = e.attr.st_ino;
  e.generation = fuse_generation;
  e.attr_timeout = 1.0;
  e.entry_timeout = 1.0;

  fuse_reply_entry (req, &e);
}

static void
glick_fs_rmdir (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  GlickMount *mount;
  GlickMountTransientFile *dir, *file;
  char *path;

  __debug__ (("glick_fs_rmdir %x %s\n", (int)parent, name));

  dir = find_parent_dir_for_path_op (req, parent, &mount);
  if (dir == NULL)
    return;

  path = g_build_filename (dir->path, name, NULL);
  if (glick_mount_lookup_path (mount, path, NULL, NULL) != NULL)
    {
      fuse_reply_err (req, EACCES);
      g_free (path);
      return;
    }

  file = g_hash_table_lookup (mount->path_to_file, path);
  if (file == NULL ||
      (file->file_ref_count == 0 && !file->owned))
    {
      fuse_reply_err (req, ENOENT);
      return;
    }
  if (!S_ISDIR (file->mode))
    {
      fuse_reply_err (req, ENOTDIR);
      return;
    }
  if (file->file_ref_count > 0)
    {
      fuse_reply_err (req, ENOTEMPTY);
      g_free (path);
      return;
    }

  /* Should be safe to free here, as kernel will drop the cache for this file
     due to the rmdir operation, and it should have no children due to above
     NOTEMPTY checks */
  glick_mount_transient_file_free (file);
  fuse_reply_err (req, 0);
}

static void
glick_fs_mknod (fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode, dev_t rdev)
{
  struct fuse_entry_param e = {0};

  e.generation = fuse_generation;

  __debug__ (("glick_fs_mknod %x %s %x %x\n", (int)parent, name, mode, (int)rdev));

  if (S_ISSOCK (mode))
    {
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
      e.generation = fuse_generation;
      e.attr_timeout = 1.0;
      e.entry_timeout = 1.0;
      e.attr.st_mode = S_IFSOCK | 0777;
      e.attr.st_nlink = 1;
      e.attr.st_size = 0;

      fuse_reply_entry (req, &e);
    }
  else if (S_ISREG (mode))
    {
      struct fuse_entry_param e = {0};
      GlickMount *mount;
      GlickMountTransientFile *dir, *file;
      char *path;


      dir = find_parent_dir_for_path_op (req, parent, &mount);
      if (dir == NULL)
	return;

      path = ensure_no_entry_for_child_op (req, mount, dir, name);
      if (path == NULL)
	return;

      file = glick_mount_transient_file_new_file (mount, dir, path);
      if (file == NULL)
	{
	  fuse_reply_err (req, ENOMEM);
	  g_free (path);
	  return;
	}

      file->mode = mode;
      g_free (path);

      glick_mount_transient_file_stat (file, &e.attr);
      e.ino = e.attr.st_ino;
      e.generation = fuse_generation;
      e.attr_timeout = 1.0;
      e.entry_timeout = 1.0;
      __debug__ (("Create regular file with inode %x\n", (int)e.ino));

      fuse_reply_entry (req, &e);
    }
  else
    fuse_reply_err (req, EPERM);

}

static void
glick_fs_unlink (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  GlickMount *mount;
  GlickMountTransientFile *dir, *file;
  char *path;

  __debug__ (("glick_fs_unlink %x %s\n", (int)parent, name));

  dir = find_parent_dir_for_path_op (req, parent, &mount);
  if (dir == NULL)
    return;

  path = g_build_filename (dir->path, name, NULL);
  if (glick_mount_lookup_path (mount, path, NULL, NULL) != NULL)
    {
      fuse_reply_err (req, EACCES);
      g_free (path);
      return;
    }

  file = g_hash_table_lookup (mount->path_to_file, path);
  if (file == NULL ||
      (file->file_ref_count == 0 && !file->owned))
    {
      fuse_reply_err (req, ENOENT);
      return;
    }
  if (S_ISDIR (file->mode))
    {
      fuse_reply_err (req, EISDIR);
      return;
    }
  if (file->file_ref_count > 0)
    {
      fuse_reply_err (req, ENOTEMPTY);
      g_free (path);
      return;
    }

  glick_mount_transient_file_free (file);
  fuse_reply_err (req, 0);
}

static struct
fuse_lowlevel_ops glick_fs_oper = {
  .lookup	= glick_fs_lookup,
  .getattr	= glick_fs_getattr,
  .opendir	= glick_fs_opendir,
  .readdir	= glick_fs_readdir,
  .releasedir	= glick_fs_releasedir,
  .readlink	= glick_fs_readlink,
  .symlink	= glick_fs_symlink,
  .open		= glick_fs_open,
  .release	= glick_fs_release,
  .read		= glick_fs_read,
  .write	= glick_fs_write,
  .setattr	= glick_fs_setattr,
  .mknod	= glick_fs_mknod,
  .unlink	= glick_fs_unlink,
  .mkdir	= glick_fs_mkdir,
  .rmdir	= glick_fs_rmdir,
};

void *
verify_header_block (char *data,
		     guint32 slice_size,
		     guint32 block_offset,
		     guint32 block_element_size,
		     guint32 block_n_elements)
{
  /* Avoid overflow in size calculation by doing it in 64bit */
  guint64 block_size = (guint64)block_element_size * (guint64)block_n_elements;

  /* Don't wrap */
  if ((guint64)block_offset + block_size < (guint64)block_offset)
    return NULL;

  /* Make sure block fits in slice */
  if ((guint64)block_offset + block_size >= (guint64)slice_size)
    return NULL;

  return data + block_offset;
}


/* Looks up or creates a new slice */
GlickSlice *
glick_slice_create (int fd,
		    guint64 slice_offset)
{
  GlickSlice *slice;
  struct stat statbuf;
  char *data;
  guint32 slice_length;
  guint64 data_offset, data_size;
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

  /* slice_length is uint32, so this can't wrap gsize */
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
glick_slice_string_equal (GlickSlice *slice, guint32 str_offset, const char *other, const char *other_end)
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
  guint16 parent_inode;

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

const char *
glick_slice_lookup_string (GlickSlice *slice, size_t offset)
{
  if (offset >= slice->strings_size)
    return NULL;

  /* TODO: Check for null termination */

  return slice->strings + offset;
}

GlickSliceInode *
glick_slice_lookup_path (GlickSlice *slice, const char *path, guint32 path_hash, guint32 *inode_num)
{
  guint32 hash_bin;
  guint32 hash_mask;
  guint32 inode;
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
	if (inode_num != NULL)
	  *inode_num = inode;
	return inodep;
      }
    }

    hash_bin = (hash_bin + step) & hash_mask;
    step++;
  }

  return NULL;
}

void
glick_mount_transient_file_own (GlickMountTransientFile *file)
{
  GlickMountTransientFile *f;

  if (!file->owned)
    {
      f = file->parent;
      while (f != NULL)
	{
	  f->file_ref_count++;
	  f = f->parent;
	}
      file->owned = TRUE;
   }
}

void
glick_mount_transient_file_unown (GlickMountTransientFile *file)
{
  if (file->owned)
    {
      GlickMountTransientFile *f = file->parent;

      while (f != NULL)
	{
	  f->file_ref_count--;
	  f = f->parent;
	}
      file->owned = FALSE;
    }
}


GlickMountTransientFile *
glick_mount_transient_file_new (GlickMount *mount, GlickMountTransientFile *parent, const char *path, gboolean owned)
{
  GlickMountTransientFile *file;

  file = g_new0 (GlickMountTransientFile, 1);
  file->path = g_strdup (path);
  file->mount = mount;
  file->fd = -1;

  /* Name references path and is the last path element, or "/" for root */
  file->name = strrchr (file->path, '/');
  if (*(file->name+1) != 0)
    file->name++;

  file->inode = mount->next_mount_file_inode++;
  file->parent = parent;

  if (parent)
    parent->children = g_list_prepend (parent->children, file);

  if (owned)
    glick_mount_transient_file_own (file);

  g_hash_table_insert (mount->inode_to_file, GUINT_TO_POINTER (file->inode), file);
  g_hash_table_insert (mount->path_to_file, file->path, file);

  return file;
}

GlickMountTransientFile *
glick_mount_transient_file_new_dir (GlickMount *mount, GlickMountTransientFile *parent, char *path, gboolean owned)
{
  GlickMountTransientFile *file = glick_mount_transient_file_new (mount, parent, path, owned);
  file->mode = S_IFDIR | 0755;

  return file;
}

GlickMountTransientFile *
glick_mount_transient_file_new_file (GlickMount *mount, GlickMountTransientFile *parent, char *path)
{
  GlickMountTransientFile *file;
  char *tmp_path;
  int fd;

  fd = g_file_open_tmp ("XXXXXX.glick", &tmp_path, NULL);
  if (fd == -1)
    return NULL;
  unlink (tmp_path);

  file = glick_mount_transient_file_new (mount, parent, path, TRUE);
  file->mode = S_IFREG | 0755;
  file->fd = fd;

  return file;
}

void
glick_mount_transient_file_stat (GlickMountTransientFile *file, struct stat *statbuf)
{
  statbuf->st_mode = file->mode;
  statbuf->st_ino = TRANSIENT_FILE_INODE(file->mount->id, file->inode);
  if (S_ISDIR (GUINT32_FROM_LE (file->mode)))
    statbuf->st_nlink = 2;
  else
    statbuf->st_nlink = 1;
  statbuf->st_size = 0;

  if (file->fd != -1)
    {
      struct stat s;
      if (fstat (file->fd, &s) == 0)
	{
	  statbuf->st_size = s.st_size;
	  statbuf->st_blksize = s.st_blksize;
	  statbuf->st_blocks = s.st_blocks;
	  statbuf->st_atime = s.st_atime;
	  statbuf->st_mtime = s.st_mtime;
	  statbuf->st_ctime = s.st_ctime;
	}
    }
}

void
glick_mount_transient_file_free (GlickMountTransientFile *file)
{
  glick_mount_transient_file_unown (file);

  if (file->parent)
    file->parent->children = g_list_remove (file->parent->children, file);

  g_assert (file->children == NULL);

  if (file->fd != -1)
    close (file->fd);

  g_free (file->data);

  g_hash_table_remove (file->mount->inode_to_file, GUINT_TO_POINTER (file->inode));
  g_hash_table_remove (file->mount->path_to_file, file->path);
  g_free (file->path);
  g_free (file);
}

GlickSliceInode *
glick_mount_lookup_path (GlickMount *mount, const char *path, GlickSlice **slice_out, guint32 *inode_num)
{
  GList *l;
  guint32 path_hash;

  path_hash = djb_hash (path);

  for (l = mount->slices; l != NULL; l = l->next)
    {
      GlickSlice *slice = l->data;
      GlickSliceInode *inode;

      inode = glick_slice_lookup_path (slice, path, path_hash, inode_num);
      if (inode != NULL)
	{
	  if (slice_out)
	    *slice_out = slice;
	  return inode;
	}
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

  mount->inode_to_file = g_hash_table_new (g_direct_hash, g_direct_equal);
  mount->path_to_file = g_hash_table_new (g_str_hash, g_str_equal);
  mount->next_mount_file_inode = 0;

  glick_mount_transient_file_new_dir (mount, NULL, "/", TRUE);

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
  gsize bufsize = fuse_chan_bufsize (ch);
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
	      __debug__ (("socket %d hung up\n", i));
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
