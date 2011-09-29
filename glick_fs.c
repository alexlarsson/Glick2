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
#include <gio/gio.h>

#include "glick.h"
#include "format.h"

/* TODO:
 * Add support for mtime/ctime/atime
 * Add bloom table for hash lookups
 * Support sha1-based merging
 * Add installed bundles symlinks
 * Support inotify for removed exported files
 * Support renames of transient files
 * Support access()
 * Support triggers
 * Do file writes in threads
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

#define BUNDLES_DIR "Apps"

typedef struct {
  int ref_count;
  guint32 id;
  int fd;
  guint64 file_size;
  guint64 slice_offset; /* File relative */
  guint64 data_offset; /* File relative */
  guint64 data_size; /* File relative */
  guint32 flags;

  char *slice_data;
  guint64 slice_size;

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
  char *bundle_id;
  char *bundle_version;
  gboolean mounted;

  GHashTable *inode_to_file;
  GHashTable *path_to_file;
  int next_mount_file_inode;

  GList *slices;
} GlickMount;

typedef struct {
  char *filename;
  time_t mtime;
  GList *slices;
} GlickPublic;

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
  int kernel_refs;

  GList *children;
};

typedef struct {
  int socket_fd;
  GlickMount *mount;
  GIOChannel *channel;
}  GlickMountRef;

typedef struct {
  int fd;
  guint64 start;
  gint64 end;
  int flags;
} GlickOpenFile;

typedef struct _GlickThreadOp GlickThreadOp;
typedef void (*GlickThreadOpFunc)(GlickThreadOp *op);

struct _GlickThreadOp {
  GlickThreadOpFunc thread_func;
  GlickThreadOpFunc result_func;
};

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

static char *glick_mountpoint = NULL;
static GThreadPool*glick_thread_pool = NULL;
static struct fuse_session *glick_fuse_session = NULL;
static GHashTable *glick_mounts_by_id; /* id -> GlickMount */
static GHashTable *glick_mounts_by_name; /* name -> GlickMount */
static GlickMount *public_mount = NULL;
static GList *glick_mounts = NULL; /* list of GlickMount */
static GList *glick_mount_refs = NULL; /* list of GlickMountRefs */
static GList *glick_publics = NULL; /* list of GlickPublic */
static int next_glick_mount_id = 3;

static GList *glick_slices = NULL; /* list of GlickSlice */
static GHashTable *glick_slices_by_id; /* id -> GlickSlice */
static guint32 next_glick_slice_id = 1;
static unsigned long fuse_generation = 1;

static int master_socket_ready_pipe = 0;
static int socket_created = 0;
static int master_socket;
static GMainLoop *mainloop;

const char *glick_slice_lookup_string (GlickSlice *slice, size_t offset);
GlickSliceInode * glick_slice_lookup_path (GlickSlice *slice, const char *path, guint32 path_hash, guint32 *inode_num);
GlickSliceInode * glick_mount_lookup_path (GlickMount *mount, const char *path, GlickSlice **slice_out, guint32 *inode_num);
GlickMountTransientFile *glick_mount_transient_file_new (GlickMount *mount, GlickMountTransientFile *parent, const char *path, gboolean owned);
GlickMountTransientFile *glick_mount_transient_file_new_dir (GlickMount *mount, GlickMountTransientFile *parent, char *path, gboolean owned);
GlickMountTransientFile *glick_mount_transient_file_new_file (GlickMount *mount, GlickMountTransientFile *parent, char *path);
void glick_mount_transient_file_stat (GlickMountTransientFile *file, struct stat *statbuf);
void glick_mount_transient_file_unown (GlickMountTransientFile *file);
void glick_mount_transient_file_own (GlickMountTransientFile *file);
void glick_mount_transient_file_unlink (GlickMountTransientFile *file);
void glick_mount_add_slice (GlickMount *mount, GlickSlice *slice);
static gboolean mount_ref_data_cb (GIOChannel   *source,
				   GIOCondition  condition,
				   gpointer      data);
void glick_public_apply_to_mount (GlickPublic *public, GlickMount *mount);
void glick_public_unapply_to_mount (GlickPublic *public, GlickMount *mount);
void glick_mount_remove_slice (GlickMount *mount, GlickSlice *slice);
void glick_thread_push (GlickThreadOp *op,
			GlickThreadOpFunc thread_func,
			GlickThreadOpFunc result_func);

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
	  GlickMountTransientFile *file;

	  file = g_hash_table_lookup (mount->inode_to_file, 0);
	  file->kernel_refs++;

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

		      file->kernel_refs++;
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
		  file->kernel_refs++;
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

  /* Never cache negative lookups, as those ares hard to invalidate
     when we add slices later */
  __debug__ (("replying with NOENT\n"));
  fuse_reply_err (req, ENOENT);
}

static void
glick_fs_forget (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
  GlickMountTransientFile *file;

  if (!INODE_IS_SLICE_FILE (ino) &&
      ino != SOCKET_INODE &&
      ino != ROOT_INODE)
    {
      file = get_transient_file_from_inode (ino, NULL);
      file->kernel_refs -= nlookup;
    }

  fuse_reply_none (req);
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

      names_used = g_hash_table_new (g_str_hash, g_str_equal);

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
      open->fd = dup (file->fd);
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
	      open->fd = dup (slice->fd);
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

  close (open->fd);
  g_free (open);
  fuse_reply_err (req, 0);
}

typedef struct {
  GlickThreadOp base;
  fuse_req_t req;
  GlickOpenFile *open;
  gssize res;
  guint64 start;
  guint64 size;
  char *buf;
  int errsv;
} GlickThreadOpRead;

static void
read_op_reply (GlickThreadOp *op)
{
  GlickThreadOpRead *read = (GlickThreadOpRead *)op;

  if (read->res >= 0)
    fuse_reply_buf (read->req, read->buf, read->res);
  else
    fuse_reply_err (read->req, read->errsv);

  free (read->buf);
}

static void
read_op_thread (GlickThreadOp *op)
{
  GlickThreadOpRead *read = (GlickThreadOpRead *)op;

  read->res = pread (read->open->fd, read->buf, read->size, read->start);
  read->errsv = errno;
}

static void
glick_fs_read (fuse_req_t req, fuse_ino_t ino, gsize size,
	       off_t off, struct fuse_file_info *fi)
{
  GlickOpenFile *open;
  guint64 start, end;
  GlickThreadOpRead *op;

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

  op = g_new0 (GlickThreadOpRead, 1);
  op->req = req;
  op->open = open;
  op->buf = malloc (size);
  op->size = size;
  op->start = start;

  glick_thread_push ((GlickThreadOp *)op,
		     read_op_thread,
		     read_op_reply);
}

static void
glick_fs_setattr (fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		  int to_set, struct fuse_file_info *fi)
{
  GlickMountTransientFile *file;
  struct stat res_stat;
  int res;

  __debug__ (("glick_fs_setattr %x to_set: %x\n", (int)ino, to_set));

  if (INODE_IS_SLICE_FILE (ino))
    {
      if (to_set == FUSE_SET_ATTR_SIZE &&
	  glick_fs_stat (ino, &res_stat) == 0 &&
	  res_stat.st_size == attr->st_size)
	{
	  __debug__ (("replying with attr\n"));
	  fuse_reply_attr (req, &res_stat, ATTR_CACHE_TIMEOUT_SEC);
	  return;
	}

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
  glick_mount_transient_file_unlink (file);
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

  glick_mount_transient_file_unlink (file);
  fuse_reply_err (req, 0);
}

static struct
fuse_lowlevel_ops glick_fs_oper = {
  .lookup	= glick_fs_lookup,
  .forget	= glick_fs_forget,
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
  if ((guint64)block_offset + block_size > (guint64)slice_size)
    return NULL;

  return data + block_offset;
}


/* Looks up or creates a new slice */
GlickSlice *
glick_slice_create (int fd, GlickSliceRef *ref)
{
  GlickSlice *slice;
  struct stat statbuf;
  char *data;
  GlickSliceHeader *header;
  guint64 slice_offset, slice_size;
  guint64 data_offset, data_size;
  guint32 flags;

  flags = GUINT32_FROM_LE (ref->flags);
  slice_offset = GUINT64_FROM_LE (ref->header_offset);
  slice_size = GUINT64_FROM_LE (ref->header_size);
  data_offset = GUINT64_FROM_LE (ref->data_offset);
  data_size = GUINT64_FROM_LE (ref->data_size);

  if (fstat (fd, &statbuf) != 0)
    return NULL;

  /* Ensure that the slice fits in the file */
  if (slice_offset >= statbuf.st_size ||
      slice_size > statbuf.st_size ||
      slice_offset > statbuf.st_size - slice_size)
    return NULL;

  /* Ensure that the data is in the file */
  if (data_offset >= statbuf.st_size ||
      data_size > statbuf.st_size ||
      data_offset > statbuf.st_size - data_size)
    return NULL;

  /* Don't wrap address space */
  if ((gsize)slice_size != slice_size)
    return NULL;

  data = mmap (NULL, slice_size, PROT_READ,
	       MAP_PRIVATE, fd, slice_offset);
  if (data == NULL)
    return NULL;

  header = (GlickSliceHeader *)data;

  slice = g_new0 (GlickSlice, 1);
  slice->ref_count = 1;

  slice->id = next_glick_slice_id++;
  if (slice->id > MAX_SLICE_ID)
    {
      g_warning ("Out of slice ids\n");
      goto error;
    }

  slice->file_size = statbuf.st_size;

  slice->flags = flags;

  slice->slice_offset = slice_offset;
  slice->slice_size = slice_size;
  slice->slice_data = data;

  slice->data_offset = data_offset;
  slice->data_size = data_size;

  slice->hash_shift = GUINT32_FROM_LE(header->hash_shift);;
  if (slice->hash_shift >= 32)
    goto error;
  slice->hash = verify_header_block (data, slice_size,
				     GUINT32_FROM_LE(header->hash_offset),
				     1U << slice->hash_shift , sizeof (GlickSliceHash));
  if (slice->hash == NULL)
    goto error;

  slice->num_inodes = GUINT32_FROM_LE(header->num_inodes);
  slice->inodes = verify_header_block (data, slice_size,
				       GUINT32_FROM_LE(header->inodes_offset),
				       slice->num_inodes, sizeof (GlickSliceInode));
  if (slice->inodes == NULL)
    goto error;

  slice->num_dirs = GUINT32_FROM_LE(header->num_dirs);
  slice->dirs = verify_header_block (data, slice_size,
				     GUINT32_FROM_LE(header->dirs_offset),
				     slice->num_dirs, sizeof (GlickSliceDirEntry));
  if (slice->dirs == NULL)
    goto error;

  slice->strings_size = GUINT32_FROM_LE(header->strings_size);
  slice->strings = verify_header_block (data, slice_size,
					GUINT32_FROM_LE(header->strings_offset),
					slice->strings_size, 1);
  if (slice->strings == NULL)
    goto error;

  slice->fd = dup (fd);

  glick_slices = g_list_prepend (glick_slices, slice);
  g_hash_table_insert (glick_slices_by_id, GINT_TO_POINTER (slice->id), slice);

  return slice;

 error:
  munmap (data, slice_size);
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
      munmap (slice->slice_data, slice->slice_size);
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
glick_mount_transient_file_unlink (GlickMountTransientFile *file)
{
  /* This will cause the file to be destroyed */
  g_hash_table_remove (file->mount->inode_to_file,
		       GUINT_TO_POINTER (file->inode));
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
      for (l = glick_publics; l != NULL; l = l->next)
	{
	  GlickPublic *public = l->data;
	  glick_public_unapply_to_mount (public, mount);
	}

      while (mount->slices != NULL)
	{
	  GlickSlice *slice = mount->slices->data;
	  glick_mount_remove_slice (mount, slice);
	  glick_slice_unref (slice);
	}

      g_hash_table_destroy (mount->inode_to_file);
      g_hash_table_destroy (mount->path_to_file);

      glick_mounts = g_list_remove (glick_mounts, mount);
      g_hash_table_remove (glick_mounts_by_id, GINT_TO_POINTER (mount->id));
      g_hash_table_remove (glick_mounts_by_name, mount->name);

      g_list_free (mount->slices);

      g_free (mount->name);
      g_free (mount->bundle_id);
      g_free (mount->bundle_version);
      g_free (mount);
    }
}

GlickMount *
glick_mount_new (const char *name)
{
  GlickMount *mount;
  GList *l;

  mount = g_new0 (GlickMount, 1);
  mount->ref_count = 1;
  mount->id = next_glick_mount_id++;

  if (mount->id > MAX_MOUNT_ID)
    {
      g_warning ("Out of mount ids");
      goto out;
    }

  if (name)
    mount->name = g_strdup (name);
  else
    mount->name = g_strdup_printf ("%d", (int)mount->id);

  mount->inode_to_file = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)glick_mount_transient_file_free);
  mount->path_to_file = g_hash_table_new (g_str_hash, g_str_equal);
  mount->next_mount_file_inode = 0;

  glick_mounts = g_list_prepend (glick_mounts, mount);
  g_hash_table_insert (glick_mounts_by_id, GINT_TO_POINTER (mount->id), mount);
  g_hash_table_insert (glick_mounts_by_name, mount->name, mount);

  /* Always want a root */
  glick_mount_transient_file_new_dir (mount, NULL, "/", TRUE);

  for (l = glick_publics; l != NULL; l = l->next)
    {
      GlickPublic *public = l->data;
      glick_public_apply_to_mount (public, mount);
    }

  return mount;

 out:
  g_free (mount);
  return NULL;
}

GlickMount *
glick_mount_new_public (void)
{
  GlickMount *mount;

  mount = glick_mount_new ("public");
  if (mount == NULL)
    return NULL;

  mount->mounted = TRUE;

  return mount;
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

GlickMount *
glick_mount_new_for_bundle (int fd)
{
  GlickMount *mount;
  GlickBundleHeader *header;
  char *data;
  gsize header_size;
  guint32 num_slices;
  guint32 slices_offset, i;
  GlickSliceRef *refs;

  data = map_and_verify_bundle (fd, &header_size);
  if (data == NULL)
    return NULL;

  header = (GlickBundleHeader *)data;

  mount = glick_mount_new (NULL);
  if (mount == NULL)
    goto out;

  slices_offset = GUINT32_FROM_LE (header->slices_offset);
  num_slices = GUINT32_FROM_LE (header->num_slices);

  refs = (GlickSliceRef *)(data + slices_offset);
  for (i = 0; i < num_slices; i++)
    {
      GlickSlice *slice = glick_slice_create (fd, &refs[i]);

      if (slice == NULL)
	  goto out;

      glick_mount_add_slice (mount, slice);
    }

  /* TODO: Verify offsets */
  mount->bundle_id = g_strndup (data + GUINT32_FROM_LE (header->bundle_id_offset),
				GUINT32_FROM_LE (header->bundle_id_size));
  mount->bundle_version = g_strndup (data + GUINT32_FROM_LE (header->bundle_version_offset),
				     GUINT32_FROM_LE (header->bundle_version_size));

  mount->mounted = TRUE;

  munmap (data, header_size);

  return mount;

 out:
  munmap (data, header_size);
  if (mount != NULL)
    glick_mount_unref (mount);
  return NULL;
}

typedef struct {
  char *path;
  guint64 size;
} AddedFile;

typedef struct {
  GlickMount *mount;
  GlickSlice *added_slice;
  AddedFile *added_files;
  int num_added_files;
} CollectInotifyData;

static void
collect_inotify_paths_cb (gpointer key,
			  gpointer value,
			  gpointer user_data)
{
  CollectInotifyData *data = user_data;
  GlickMountTransientFile *file = value;
  GlickSlice *slice = data->added_slice;
  guint32 path_hash;
  guint32 inode_num;
  GlickSliceInode *inode;
  guint64 dirent, last_dirent, i;

  if (file->kernel_refs > 0)
    {
      path_hash = djb_hash (file->path);
      inode = glick_slice_lookup_path (slice, file->path,
				       path_hash, &inode_num);
      if (inode != NULL && S_ISDIR (GUINT32_FROM_LE (inode->mode)))
	{
	  dirent = GUINT64_FROM_LE (inode->offset);
	  last_dirent = dirent + GUINT64_FROM_LE (inode->size);
	  dirent = MIN (dirent, slice->num_dirs);
	  last_dirent = MIN (last_dirent, slice->num_dirs);

	  data->added_files = g_new0 (AddedFile, last_dirent - dirent);
	  for (i = dirent; i < last_dirent; i++)
	    {
	      guint16 entry_inode = GUINT16_FROM_LE (slice->dirs[i].inode);
	      if (entry_inode < slice->num_inodes)
		{
		  const char *name = glick_slice_lookup_string (slice,
								GUINT32_FROM_LE (slice->inodes[entry_inode].name));
		  if (name != NULL)
		    {
		      data->added_files[data->num_added_files].path = g_build_filename (glick_mountpoint, data->mount->name, file->path, name, NULL);
		      data->added_files[data->num_added_files].size = GUINT64_FROM_LE (slice->inodes[entry_inode].size);
		      data->num_added_files++;
		    }
		}
	    }
	}
    }
}

typedef struct {
  GlickThreadOp base;
  AddedFile *added_files;
  int num_added_files;
} GlickThreadOpChanges;

static void
changes_op_thread (GlickThreadOp *op)
{
  GlickThreadOpChanges *changes = (GlickThreadOpChanges *)op;
  int i;

  for (i = 0; i < changes->num_added_files; i++)
    {
      AddedFile *added_file = &changes->added_files[i];
      truncate (added_file->path, added_file->size);
      g_free (added_file->path);
    }

  g_free (changes->added_files);
}

void
glick_mount_add_slice (GlickMount *mount, GlickSlice *slice)
{
  CollectInotifyData data = { 0 };

  mount->slices = g_list_prepend (mount->slices, slice);

  if (mount->mounted &&
      (slice->flags & GLICK_SLICE_FLAGS_EXPORT))
    {
      data.added_slice = slice;
      data.added_files = NULL;
      data.mount = mount;
      g_hash_table_foreach (mount->inode_to_file,
			    collect_inotify_paths_cb,
			    &data);

      if (data.added_files)
	{
	  GlickThreadOpChanges *op;

	  op = g_new0 (GlickThreadOpChanges, 1);
	  op->added_files = data.added_files;
	  op->num_added_files = data.num_added_files;

	  glick_thread_push ((GlickThreadOp *)op,
			     changes_op_thread, NULL);
	}
    }
}

struct RemoveData {
  GlickMount *mount;
  GlickSlice *removed_slice;
};

static gboolean
remove_slice_cb (gpointer key,
		 gpointer value,
		 gpointer user_data)
{
  struct RemoveData *data = user_data;
  GlickMountTransientFile *file = value;
  GlickMount *mount = data->mount;
  GlickSlice *removed_slice = data->removed_slice;
  GlickSliceInode *inode;
  guint32 path_hash;
  guint32 inode_num;
  guint64 dirent, last_dirent, i;

  if (file->kernel_refs > 0)
    {
      fuse_ino_t fuse_inode;
      struct fuse_chan *ch = fuse_session_next_chan (glick_fuse_session, NULL);

      path_hash = djb_hash (file->path);
      inode = glick_slice_lookup_path (removed_slice, file->path, path_hash, &inode_num);
      if (inode != NULL && S_ISDIR (GUINT32_FROM_LE (inode->mode)))
	{
	  fuse_inode = TRANSIENT_FILE_INODE(mount->id, file->inode);
	  dirent = GUINT64_FROM_LE (inode->offset);
	  last_dirent = dirent + GUINT64_FROM_LE (inode->size);
	  dirent = MIN (dirent, removed_slice->num_dirs);
	  last_dirent = MIN (last_dirent, removed_slice->num_dirs);
	  for (i = dirent; i < last_dirent; i++)
	    {
	      guint16 entry_inode = GUINT16_FROM_LE (removed_slice->dirs[i].inode);
	      if (entry_inode < removed_slice->num_inodes)
		{
		  const char *name = glick_slice_lookup_string (removed_slice,
								GUINT32_FROM_LE (removed_slice->inodes[entry_inode].name));
		  if (name != NULL)
		    fuse_lowlevel_notify_inval_entry (ch, fuse_inode, name, strlen (name));
		}
	    }
	}
    }

  if (file->file_ref_count > 0 || file->owned)
    return FALSE;

  inode = glick_mount_lookup_path (mount, file->path, NULL, NULL);

  /* Free file if no more slices references it */
  return inode == NULL;
}

void
glick_mount_remove_slice (GlickMount *mount, GlickSlice *slice)
{
  struct RemoveData data;

  data.mount = mount;
  data.removed_slice = slice;

  mount->slices = g_list_remove (mount->slices, slice);
  g_hash_table_foreach_remove (mount->inode_to_file,
			       remove_slice_cb,
			       &data);
}

GlickMountRef *
glick_mount_ref_new (int fd)
{
  GlickMountRef *ref;

  ref = g_new0 (GlickMountRef, 1);
  ref->socket_fd = fd;

  glick_mount_refs = g_list_prepend (glick_mount_refs, ref);

  ref->channel = g_io_channel_unix_new (fd);

  g_io_add_watch (ref->channel, G_IO_IN | G_IO_HUP, mount_ref_data_cb, ref);

  return ref;
}

void
glick_mount_ref_free (GlickMountRef *ref)
{
  glick_mount_refs = g_list_remove (glick_mount_refs, ref);

  if (ref->mount)
    glick_mount_unref (ref->mount);

  g_io_channel_unref (ref->channel);
  close (ref->socket_fd);
  g_free (ref);
}

void
glick_mount_ref_handle_request (GlickMountRef *ref,
				GlickMountRequestMsg *request,
				int fd)
{
  GlickMountRequestReply reply;

  memset (&reply, 0, sizeof (reply));

  if (ref->mount != NULL)
    {
      reply.result = 3;
      goto out;
    }

  ref->mount = glick_mount_new_for_bundle (fd);
  if (ref->mount == NULL)
    {
      reply.result = 4;
      goto out;
    }

  reply.result = 0;
  strncpy (reply.name, ref->mount->name, sizeof (reply.name));

 out:
  send (ref->socket_fd, &reply, sizeof (reply), 0);
  close (fd);
}

void
glick_public_apply_to_mount (GlickPublic *public, GlickMount *mount)
{
  GList *l;

  for (l = public->slices; l != NULL; l = l->next)
    {
      GlickSlice *slice = l->data;
      glick_mount_add_slice (mount, slice);
    }
}

void
glick_public_unapply_to_mount (GlickPublic *public, GlickMount *mount)
{
  GList *l;

  for (l = public->slices; l != NULL; l = l->next)
    {
      GlickSlice *slice = l->data;
      glick_mount_remove_slice (mount, slice);
    }
}


GlickPublic *
glick_public_new (char *filename)
{
  char *data;
  gsize header_size;
  GlickBundleHeader *header;
  guint32 num_slices;
  guint32 slices_offset, i;
  GlickSliceRef *refs;
  GList *l;
  GlickPublic *public;
  struct stat statbuf;

  int fd = open (filename, O_RDONLY);
  if (fd == -1)
    return NULL;

  if (fstat (fd, &statbuf) != 0)
    return NULL;

  data = map_and_verify_bundle (fd, &header_size);
  if (data == NULL)
    return NULL;

  public = g_new0 (GlickPublic, 1);
  public->filename = g_strdup (filename);
  public->mtime = statbuf.st_mtime;

  header = (GlickBundleHeader *)data;

  slices_offset = GUINT32_FROM_LE (header->slices_offset);
  num_slices = GUINT32_FROM_LE (header->num_slices);

  refs = (GlickSliceRef *)(data + slices_offset);
  for (i = 0; i < num_slices; i++)
    {
      GlickSliceRef *ref = &refs[i];
      guint32 flags = GUINT32_FROM_LE (ref->flags);

      if (flags & GLICK_SLICE_FLAGS_EXPORT)
	{
	  GlickSlice *slice = glick_slice_create (fd, ref);

	  if (slice)
	    public->slices = g_list_prepend (public->slices, slice);
	}
    }

  munmap (data, header_size);

  glick_publics = g_list_prepend (glick_publics, public);

  for (l = glick_mounts; l != NULL; l = l->next)
    {
      GlickMount *mount = l->data;

      glick_public_apply_to_mount (public, mount);
    }

  return public;
}

void
glick_public_free (GlickPublic *public)
{
  GList *l;

  glick_publics = g_list_remove (glick_publics, public);

  for (l = glick_mounts; l != NULL; l = l->next)
    {
      GlickMount *mount = l->data;

      glick_public_unapply_to_mount (public, mount);
    }

  for (l = public->slices; l != NULL; l = l->next)
    {
      GlickSlice *slice = l->data;
      glick_slice_unref (slice);
    }
  g_list_free (public->slices);

  g_free (public->filename);
  g_free (public);
}

static GlickPublic *
find_public_for_file (GList *list, const char *path)
{
  GList *l;

  for (l = list; l != NULL; l = l->next)
    {
      GlickPublic *public = l->data;

      if (strcmp (public->filename, path) == 0)
	return public;
    }

  return NULL;
}

static void
scan_public_directory (const char *path)
{
  GDir *dir;
  const char *child_name;
  char *child_path;
  GList *publics;
  struct stat statbuf;
  GlickPublic *old_public;
  GList *l;

  publics = g_list_copy (glick_publics);

  dir = g_dir_open (path, 0, NULL);
  if (dir != NULL)
    {
      while ((child_name = g_dir_read_name (dir)) != NULL)
	{
	  if (*child_name == '.')
	    continue;

	  child_path = g_build_filename (path, child_name, NULL);

	  if (stat (child_path, &statbuf) == 0 &&
	      S_ISREG (statbuf.st_mode))
	    {
	      old_public = find_public_for_file (publics, child_path);
	      if (old_public == NULL)
		{
		  glick_public_new (child_path);
		}
	      else
		{
		  publics = g_list_remove (publics, old_public);

		  if (old_public->mtime != statbuf.st_mtime)
		    {
		      glick_public_free (old_public);
		      glick_public_new (child_path);
		    }
		}
	    }

	  g_free (child_path);
	}
      g_dir_close (dir);
    }

  for (l = publics; l != NULL; l = l->next)
    {
      old_public = l->data;
      glick_public_free (old_public);
    }
  g_list_free (publics);
}

static gboolean
mount_ref_data_cb (GIOChannel   *source,
		   GIOCondition  condition,
		   gpointer      data)
{
  GlickMountRef *ref = data;

  if (condition & G_IO_HUP)
    {
      __debug__ (("socket %d hung up\n", ref->socket_fd));
      glick_mount_ref_free (ref);
      return FALSE;
    }

  if (condition & G_IO_IN)
    {
      int res, passed_fd;
      GlickMountRequestMsg request;
      GlickMountRequestReply reply;

      memset (&reply, 0, sizeof (reply));
      res = recv_socket_message (ref->socket_fd, (char *)&request, sizeof (request), &passed_fd);
      if (res != -1)
	{
	  if (res == 0 || passed_fd == -1)
	    {
	      fprintf (stderr, "Empty request\n");
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

  return TRUE;
}

static gboolean
got_fuse_request (GIOChannel   *source,
		  GIOCondition  condition,
		  gpointer      data)
{
  struct fuse_session *se = data;
  struct fuse_chan *ch = fuse_session_next_chan (se, NULL);
  struct fuse_chan *tmpch = ch;
  gsize bufsize = fuse_chan_bufsize (ch);
  char *buf = g_malloc (bufsize);
  int res;

 retry:
  res = fuse_chan_recv (&tmpch, buf, bufsize);
  if (res == -EINTR)
    goto retry;
  if (res > 0)
    fuse_session_process (se, buf, res, tmpch);

  g_free (buf);

  if (fuse_session_exited (se))
    {
      g_main_loop_quit (mainloop);
      return FALSE;
    }

  return TRUE;
}

static gboolean
new_client_cb (GIOChannel   *source,
	       GIOCondition  condition,
	       gpointer      data)
{
  int res;

  res = accept (master_socket, NULL, NULL);

  if (res == -1)
    perror ("accept");
  else
    {
      glick_mount_ref_new (res);
    }

  return TRUE;
}

static gboolean
ready_pipe_cb (GIOChannel   *source,
	       GIOCondition  condition,
	       gpointer      data)
{
  GIOChannel *channel = data;
  GIOChannel *master_channel;
  int res;

  /* Waiting for master socket to be ready */
  res = listen (master_socket, 5);
  if (res == -1)
    perror ("listen");

  close (master_socket_ready_pipe);
  master_socket_ready_pipe = 0;

  g_io_channel_unref (channel);

  master_channel = g_io_channel_unix_new (master_socket);
  g_io_add_watch (master_channel, G_IO_IN, new_client_cb, master_channel);

  return FALSE;
}

static void exit_handler(int sig)
{
  (void) sig;
  g_main_loop_quit (mainloop);
}

static int set_one_signal_handler(int sig, void (*handler)(int))
{
  struct sigaction sa;
  struct sigaction old_sa;

  memset (&sa, 0, sizeof (struct sigaction));
  sa.sa_handler = handler;
  sigemptyset (&(sa.sa_mask));
  sa.sa_flags = 0;

  if (sigaction (sig, NULL, &old_sa) == -1)
    return FALSE;

  if (old_sa.sa_handler == SIG_DFL &&
      sigaction(sig, &sa, NULL) == -1)
    return FALSE;

  return TRUE;
}

static void
bundles_dir_changed (GFileMonitor      *monitor,
		     GFile             *file,
		     GFile             *other_file,
		     GFileMonitorEvent  event_type,
		     char *bundle_dir)
{
  if (event_type == G_FILE_MONITOR_EVENT_CREATED ||
      event_type == G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT ||
      event_type == G_FILE_MONITOR_EVENT_DELETED)
    {
      scan_public_directory (bundle_dir);
    }
}

int
main_loop (struct fuse_session *se)
{
  int res = 0;
  struct fuse_chan *ch = fuse_session_next_chan (se, NULL);
  int fuse_fd = fuse_chan_fd (ch);
  GIOChannel *fuse_channel, *ready_pipe_channel;
  char *bundle_dir;

  glick_fuse_session = se;

  mainloop = g_main_loop_new (NULL, TRUE);

  if (set_one_signal_handler(SIGHUP, exit_handler) == -1 ||
      set_one_signal_handler(SIGINT, exit_handler) == -1 ||
      set_one_signal_handler(SIGTERM, exit_handler) == -1 ||
      set_one_signal_handler(SIGPIPE, SIG_IGN) == -1)
    return -1;

  public_mount = glick_mount_new_public ();

  fuse_channel = g_io_channel_unix_new (fuse_fd);
  g_io_add_watch (fuse_channel, G_IO_IN, got_fuse_request, se);

  ready_pipe_channel = g_io_channel_unix_new (master_socket_ready_pipe);
  g_io_add_watch (ready_pipe_channel, G_IO_IN, ready_pipe_cb, ready_pipe_channel);

  bundle_dir = g_build_filename (g_get_home_dir (), BUNDLES_DIR, NULL);
  scan_public_directory (bundle_dir);

  {
    GFile *f = g_file_new_for_path (bundle_dir);
    GFileMonitor *monitor =
      g_file_monitor_directory (f, G_FILE_MONITOR_NONE,
				NULL, NULL);

    g_signal_connect (monitor, "changed", G_CALLBACK (bundles_dir_changed), bundle_dir);
  }

  g_main_loop_run (mainloop);

  fuse_session_reset (se);

  return res < 0 ? -1 : 0;
}

void
glick_thread_push (GlickThreadOp *op,
		   GlickThreadOpFunc thread_func,
		   GlickThreadOpFunc result_func)
{
  op->thread_func = thread_func;
  op->result_func = result_func;
  g_thread_pool_push (glick_thread_pool,
		      op, NULL);
}

static gboolean
mainloop_proxy_func (gpointer user_data)
{
  GlickThreadOp *op = user_data;

  op->result_func (op);

  g_free (op);

  return FALSE;
}

static void
thread_pool_func (gpointer data,
		  gpointer user_data)
{
  GlickThreadOp *op = data;
  GSource *source;

  op->thread_func (op);

  if (op->result_func)
    {
      source = g_idle_source_new ();
      g_source_set_priority (source, G_PRIORITY_DEFAULT);
      g_source_set_callback (source, mainloop_proxy_func, op,
			     NULL);
      g_source_attach (source, NULL);
      g_source_unref (source);
    }
  else
    g_free (op);
}

int
main (int argc, char *argv[])
{
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  struct fuse_chan *ch;
  int err = -1;
  const char *homedir;

  g_thread_init (NULL);
  g_type_init ();

  glick_thread_pool = g_thread_pool_new (thread_pool_func, NULL, 20,
					 FALSE, NULL);

  glick_mounts_by_id = g_hash_table_new (g_direct_hash, g_direct_equal);
  glick_mounts_by_name = g_hash_table_new (g_str_hash, g_str_equal);
  glick_slices_by_id = g_hash_table_new (g_direct_hash, g_direct_equal);

  homedir = g_get_home_dir ();
  glick_mountpoint = g_build_filename (homedir, ".glick", NULL);
  mkdir (glick_mountpoint, 0700);

  if ((ch = fuse_mount (glick_mountpoint, NULL)) != NULL)
    {
      struct fuse_session *se;

      se = fuse_lowlevel_new (&args, &glick_fs_oper,
			      sizeof glick_fs_oper, NULL);
      if (se != NULL)
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

	    socket_path = g_build_filename (glick_mountpoint, SOCKET_NAME, NULL);

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
	  fuse_session_remove_chan (ch);

	  fuse_session_destroy (se);
	}
      fuse_unmount (glick_mountpoint, ch);
    }
  fuse_opt_free_args (&args);

  return err ? 1 : 0;
}
