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
 * Add support for mtime/ctime/atime in slices
 * Add bloom table for hash lookups
 * Support sha1-based merging
 * Support access()
 * Do file writes in threads
 * Use sha1 at the file level
 * use bup-style hashing for file parts
 * debug why gnome-shell doesn't pick up removal of bundle desktop files
 * Use hash-split?
 * Compressed files
 * Reuse mount with same fd as other mountref
 */

typedef enum {
  GLICK_INODE_FLAGS_NONE = 0,
  GLICK_INODE_FLAGS_OWNED = 1 << 0,
  GLICK_INODE_FLAGS_HIDDEN = 1 << 1,
  GLICK_INODE_FLAGS_REMOVABLE = 1 << 2,
  GLICK_INODE_FLAGS_IMMUTABLE = 1 << 3
} GlickInodeFlags;

typedef enum {
  GLICK_INODE_TYPE_DIR,
  GLICK_INODE_TYPE_SOCKET,
  GLICK_INODE_TYPE_TRANSIENT_FILE,
  GLICK_INODE_TYPE_TRANSIENT_SYMLINK,
  GLICK_INODE_TYPE_SLICE_FILE
} GlickInodeType;

#define BUNDLES_DIR "Apps"

typedef struct GlickInodeDir GlickInodeDir;

typedef struct {
  int ref_count;
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

typedef enum {
  GLICK_TRIGGER_FLAGS_NONE = 0,
  GLICK_TRIGGER_FLAGS_CREATE_DIRECTORY = 1 << 1,
  GLICK_TRIGGER_FLAGS_BUMP_DIR_MTIME = 1 << 2,
} GlickTriggerFlags;

typedef struct {
  char *directory;
  char *cmdline;
  guint32 flags;
  guint tag;
} GlickTrigger;

typedef struct {
  char *name;
  int ref_count;
  unsigned long id;
  char *bundle_id;
  char *bundle_version;
  gboolean mounted;

  GlickInodeDir *dir;
  GList *slices;
  GList *triggers;
} GlickMount;

typedef struct {
  char *filename;
  time_t mtime;
  char *bundle_id;
  GList *slices;
  guint32 id;
} GlickPublic;

typedef struct _GlickInode GlickInode;
struct _GlickInode {
  int ref_count;
  fuse_ino_t fuse_inode;
  guint32 kernel_ref_count;
  guint32 type;
  guint32 flags;

  mode_t mode;
  time_t atime;
  time_t mtime;
  time_t ctime;
};

struct GlickInodeDir {
  GlickInode base;
  GlickInodeDir *parent;
  GHashTable *known_children; // name -> GlickInode *
  GlickMount *mount;
  char *mount_path;
};

typedef struct {
  GlickInode base;
} GlickInodeSocket;

typedef struct {
  GlickInode base;
  int fd;
} GlickInodeTransient;

typedef struct {
  GlickInode base;
  char *symlink;
} GlickInodeSymlink;

typedef struct {
  GlickInode base;
  GlickSlice *slice;
  GlickSliceInode *slice_inode;
} GlickInodeSliceFile;

typedef union {
  GlickInode base;
  GlickInodeDir dir;
  GlickInodeSocket socket;
  GlickInodeTransient transient;
  GlickInodeSymlink symlink;
  GlickInodeSliceFile file;
} GlickInodeAll;

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

#define SOCKET_NAME "socket"

#define ENTRY_CACHE_TIMEOUT_SEC 10000
#define ATTR_CACHE_TIMEOUT_SEC 10000

static GlickInodeDir *glick_root;
static GlickInodeDir *glick_bundles_dir;
static GHashTable *glick_inodes; /* inode -> GlickInode */
static fuse_ino_t glick_inode_counter = 1;
static char *glick_mountpoint = NULL;
static GThreadPool*glick_thread_pool = NULL;
static struct fuse_session *glick_fuse_session = NULL;
static GlickMount *public_mount = NULL;
static GList *glick_mounts = NULL; /* list of GlickMount */
static GList *glick_mount_refs = NULL; /* list of GlickMountRefs */
static GList *glick_publics = NULL; /* list of GlickPublic */
static int next_glick_mount_id = 4;

static GList *glick_slices = NULL; /* list of GlickSlice */
static guint32 next_glick_public_id = 1;
static unsigned long fuse_generation = 1;

static int master_socket_ready_pipe = 0;
static int master_socket;
static GMainLoop *mainloop;

static GlickTrigger builtin_public_triggers[] = {
  {
    "/share/icons/hicolor",
    "gtk-update-icon-cache -t %d",
    GLICK_TRIGGER_FLAGS_BUMP_DIR_MTIME | GLICK_TRIGGER_FLAGS_CREATE_DIRECTORY,
  },
  {
    "/share/applications",
    "update-desktop-database %d",
    GLICK_TRIGGER_FLAGS_CREATE_DIRECTORY,
  }
};

const char *glick_slice_lookup_string (GlickSlice *slice, size_t offset);
GlickSliceInode * glick_slice_lookup_path (GlickSlice *slice, const char *path, guint32 path_hash, guint32 *inode_num);
GlickSliceInode * glick_mount_lookup_path (GlickMount *mount, const char *path, GlickSlice **slice_out, guint32 *inode_num);
void glick_mount_add_slice (GlickMount *mount, GlickSlice *slice);
static gboolean mount_ref_data_cb (GIOChannel   *source,
				   GIOCondition  condition,
				   gpointer      data);
GlickPublic *glick_public_lookup_by_id (guint32 id);
GlickPublic *glick_public_lookup_by_bundle (const char *bundle_id);
void glick_public_apply_to_mount (GlickPublic *public, GlickMount *mount);
void glick_public_unapply_to_mount (GlickPublic *public, GlickMount *mount);
void glick_mount_remove_slice (GlickMount *mount, GlickSlice *slice);
void glick_thread_push (GlickThreadOp *op,
			GlickThreadOpFunc thread_func,
			GlickThreadOpFunc result_func);
GlickSliceInode *glick_slice_get_inode (GlickSlice *slice, int local);
void glick_mount_unref (GlickMount *mount);
void glick_slice_unref (GlickSlice *slice);
GlickSlice *glick_slice_ref (GlickSlice *slice);
static void glick_inode_dir_remove_stale_children (GlickInodeDir *dir);
static void glick_inode_dir_remove_all_children (GlickInodeDir *dir);
static gboolean glick_inode_is_owned (GlickInode *inode);
void glick_mount_real_remove_slice (GlickMount *mount, GlickSlice *slice);

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

static GlickInode *
glick_inode_new (guint32 type)
{
  GlickInodeAll *all;
  time_t now;

  all = g_slice_new0 (GlickInodeAll);
  all->base.type = type;
  all->base.ref_count = 1;
  all->base.fuse_inode = glick_inode_counter++;

  now = time(NULL);
  all->base.atime = now;
  all->base.ctime = now;
  all->base.mtime = now;

  g_hash_table_insert (glick_inodes, GINT_TO_POINTER (all->base.fuse_inode), all);

  return (GlickInode *)all;
}

static GlickInode *
glick_inode_ref (GlickInode *inode)
{
  inode->ref_count++;
  return inode;
}

static void
glick_inode_unref (GlickInode *inode)
{
  inode->ref_count--;
  if (inode->ref_count > 0)
    return;

  switch (inode->type) {
  case GLICK_INODE_TYPE_DIR:
    {
      GlickInodeDir *dir = (GlickInodeDir *)inode;
      g_assert (g_hash_table_size (dir->known_children) == 0);
      g_hash_table_destroy (dir->known_children);
      if (dir->mount)
	{
	  g_free (dir->mount_path);
	}
      break;
    }
  case GLICK_INODE_TYPE_SOCKET:
    break;
  case GLICK_INODE_TYPE_TRANSIENT_FILE:
    {
      GlickInodeTransient *transient = (GlickInodeTransient *)inode;
      close (transient->fd);
    }
    break;
  case GLICK_INODE_TYPE_TRANSIENT_SYMLINK:
    {
      GlickInodeSymlink *symlink = (GlickInodeSymlink *)inode;
      g_free (symlink->symlink);
    }
    break;
  case GLICK_INODE_TYPE_SLICE_FILE:
    {
      GlickInodeSliceFile *file = (GlickInodeSliceFile *)inode;
      glick_slice_unref (file->slice);
    }
    break;
  }
  g_hash_table_remove (glick_inodes, GINT_TO_POINTER (inode->fuse_inode));
  g_slice_free (GlickInodeAll, (GlickInodeAll*)inode);
}

static void
glick_inode_dir_add_child (GlickInodeDir *dir, const char *name, GlickInode *child)
{
  g_assert (g_hash_table_lookup (dir->known_children, name) == NULL);
  g_hash_table_insert (dir->known_children, g_strdup (name), glick_inode_ref (child));

  if (child->type == GLICK_INODE_TYPE_DIR)
    {
      GlickInodeDir *child_dir = (GlickInodeDir *)child;
      child_dir->parent = dir;

      if (dir->mount != NULL)
	{
	  child_dir->mount = dir->mount;
	  child_dir->mount_path = g_build_filename (dir->mount_path, name, NULL);
	}
    }
}

static void
glick_inode_dir_remove_child (GlickInodeDir *dir, const char *name, gboolean invalidate)
{
  GlickInode *child;

  child = g_hash_table_lookup (dir->known_children, name);
  g_assert (child != NULL);
  g_hash_table_remove (dir->known_children, name);

  if (child->kernel_ref_count > 0 && invalidate)
    {
      struct fuse_chan *ch = fuse_session_next_chan (glick_fuse_session, NULL);

      fuse_lowlevel_notify_inval_entry (ch, dir->base.fuse_inode, name, strlen (name));
    }
}

static gboolean
remove_stale_children (gpointer  key,
		       gpointer  value,
		       gpointer  user_data)
{
  GlickInodeDir *dir = user_data;
  const char *name = key;
  GlickInode *child = value;
  GlickSliceInode *inodep;
  char *path;

  if (child->type == GLICK_INODE_TYPE_DIR)
    {
      GlickInodeDir *child_dir = (GlickInodeDir *)child;
      glick_inode_dir_remove_stale_children (child_dir);

      if (g_hash_table_size (child_dir->known_children) > 0)
	return FALSE;
    }

  if (glick_inode_is_owned (child))
    return FALSE;

  if (dir->mount != NULL)
    {
      path = g_build_filename (dir->mount_path, name, NULL);
      inodep = glick_mount_lookup_path (dir->mount, path, NULL, NULL);
      g_free (path);
      if (inodep != NULL)
	return FALSE;
    }

  if (child->kernel_ref_count > 0)
    {
      struct fuse_chan *ch = fuse_session_next_chan (glick_fuse_session, NULL);

      fuse_lowlevel_notify_inval_entry (ch, dir->base.fuse_inode, name, strlen (name));
    }

  return TRUE;
}

static void
glick_inode_dir_remove_stale_children (GlickInodeDir *dir)
{
  g_hash_table_foreach_remove (dir->known_children, remove_stale_children, dir);
}

static gboolean
remove_all_children (gpointer  key,
		     gpointer  value,
		     gpointer  user_data)
{
  GlickInodeDir *dir = user_data;
  const char *name = key;
  GlickInode *child = value;

  if (child->type == GLICK_INODE_TYPE_DIR)
    {
      GlickInodeDir *child_dir = (GlickInodeDir *)child;
      glick_inode_dir_remove_all_children (child_dir);
    }

  if (child->kernel_ref_count > 0)
    {
      struct fuse_chan *ch = fuse_session_next_chan (glick_fuse_session, NULL);

      fuse_lowlevel_notify_inval_entry (ch, dir->base.fuse_inode, name, strlen (name));
    }

  return TRUE;
}

static void
glick_inode_dir_remove_all_children (GlickInodeDir *dir)
{
  g_hash_table_foreach_remove (dir->known_children, remove_all_children, dir);
}

static void
glick_inode_set_flags (GlickInode *inode, guint32 flags)
{
  inode->flags |= flags;
}

static void
glick_inode_unset_flags (GlickInode *inode, guint32 flags)
{
  inode->flags &= ~flags;
}

static gboolean
glick_inode_is_owned (GlickInode *inode)
{
  return (inode->flags & GLICK_INODE_FLAGS_OWNED) != 0;
}

static void
glick_inode_own (GlickInode *inode)
{
  glick_inode_set_flags (inode, GLICK_INODE_FLAGS_OWNED);
}

static void
glick_inode_unown (GlickInode *inode)
{
  glick_inode_unset_flags (inode, GLICK_INODE_FLAGS_OWNED);
}

static gboolean
glick_inode_is_hidden (GlickInode *inode)
{
  return (inode->flags & GLICK_INODE_FLAGS_HIDDEN) != 0;
}

static void
glick_inode_hide (GlickInode *inode)
{
  glick_inode_set_flags (inode, GLICK_INODE_FLAGS_HIDDEN);
}

static void
glick_inode_unhide (GlickInode *inode)
{
  glick_inode_unset_flags (inode, GLICK_INODE_FLAGS_HIDDEN);
}

static gboolean
glick_inode_is_removable (GlickInode *inode)
{
  return (inode->flags & GLICK_INODE_FLAGS_REMOVABLE) != 0;
}

static void
glick_inode_set_removable (GlickInode *inode, gboolean removable)
{
  if (removable)
    glick_inode_set_flags (inode, GLICK_INODE_FLAGS_REMOVABLE);
  else
    glick_inode_unset_flags (inode, GLICK_INODE_FLAGS_REMOVABLE);
}

static gboolean
glick_inode_is_immutable (GlickInode *inode)
{
  return (inode->flags & GLICK_INODE_FLAGS_IMMUTABLE) != 0;
}

static void
glick_inode_set_immutable (GlickInode *inode, gboolean immutable)
{
  if (immutable)
    glick_inode_set_flags (inode, GLICK_INODE_FLAGS_IMMUTABLE);
  else
    glick_inode_unset_flags (inode, GLICK_INODE_FLAGS_IMMUTABLE);
}

static GlickInodeDir *
glick_inode_new_dir (void)
{
  GlickInodeDir *dir = (GlickInodeDir *)glick_inode_new (GLICK_INODE_TYPE_DIR);

  dir->base.mode = S_IFDIR | 0755;
  dir->known_children = g_hash_table_new_full (g_str_hash, g_str_equal,
					       g_free, (GDestroyNotify)glick_inode_unref);

  return dir;
}

static GlickInodeSliceFile *
glick_inode_new_slice_file (GlickSlice *slice, GlickSliceInode *slice_inode)
{
  GlickInodeSliceFile *file = (GlickInodeSliceFile *)glick_inode_new (GLICK_INODE_TYPE_SLICE_FILE);
  file->slice = glick_slice_ref (slice);
  file->slice_inode = slice_inode;
  file->base.mode = GUINT16_FROM_LE (slice_inode->mode);

  return file;
}

static GlickInodeSocket *
glick_inode_new_socket (void)
{
  GlickInodeSocket *socket = (GlickInodeSocket *)glick_inode_new (GLICK_INODE_TYPE_SOCKET);

  socket->base.mode = S_IFSOCK | 0755;

  return socket;
}

static GlickInodeTransient *
glick_inode_new_transient (void)
{
  GlickInodeTransient *transient;
  char *tmp_path;
  int fd;

  fd = g_file_open_tmp ("XXXXXX.glick", &tmp_path, NULL);
  if (fd == -1)
    return NULL;
  unlink (tmp_path);

  transient = (GlickInodeTransient *)glick_inode_new (GLICK_INODE_TYPE_TRANSIENT_FILE);
  transient->fd = fd;
  transient->base.mode = S_IFREG | 0755;
  return transient;
}

static GlickInodeSymlink *
glick_inode_new_symlink (const char *data)
{
  GlickInodeSymlink *symlink;

  symlink = (GlickInodeSymlink *)glick_inode_new (GLICK_INODE_TYPE_TRANSIENT_SYMLINK);
  symlink->symlink = g_strdup (data);
  symlink->base.mode = S_IFLNK | 0755;
  return symlink;
}

static void
glick_inode_stat (GlickInode *inode, struct stat *statbuf)
{
  statbuf->st_ino = inode->fuse_inode;
  statbuf->st_nlink = 1;
  statbuf->st_size = 0;
  statbuf->st_mode = inode->mode;
  statbuf->st_atime = inode->atime;
  statbuf->st_mtime = inode->mtime;
  statbuf->st_ctime = inode->ctime;

  switch (inode->type) {
  case GLICK_INODE_TYPE_DIR:
    {
      GlickInodeDir *dir = (GlickInodeDir *)inode;
      statbuf->st_nlink = 1 + g_hash_table_size (dir->known_children);
      break;
    }
  case GLICK_INODE_TYPE_SOCKET:
    break;
  case GLICK_INODE_TYPE_TRANSIENT_FILE:
    {
      GlickInodeTransient *transient = (GlickInodeTransient *)inode;
      struct stat s;
      if (fstat (transient->fd, &s) == 0)
	{
	  statbuf->st_size = s.st_size;
	  statbuf->st_blksize = s.st_blksize;
	  statbuf->st_blocks = s.st_blocks;
	  statbuf->st_atime = s.st_atime;
	  statbuf->st_mtime = s.st_mtime;
	  statbuf->st_ctime = s.st_ctime;
	}
    }
    break;
  case GLICK_INODE_TYPE_TRANSIENT_SYMLINK:
    break;
  case GLICK_INODE_TYPE_SLICE_FILE:
    {
      GlickInodeSliceFile *file = (GlickInodeSliceFile *)inode;
      statbuf->st_size = GUINT64_FROM_LE (file->slice_inode->size);
    }
    break;
  }
}

/********************* FUSE Helpers ********************/

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

/********************* FUSE Implementation ********************/

static GlickInode *
create_child_from_slice_inode (GlickInodeDir *parent_inode, const char *name,
			       GlickSliceInode *slice_inode, GlickSlice *slice, guint32 inode_num)
{
  guint32 mode = GUINT16_FROM_LE (slice_inode->mode);
  GlickInodeDir *dir;
  GlickInode *inode;

  if (S_ISDIR (mode))
    {
      dir = glick_inode_new_dir ();
      dir->base.mode = mode;
      inode = (GlickInode *)dir;
    }
  else
    {
      inode = (GlickInode *)glick_inode_new_slice_file (slice, slice_inode);
    }

  glick_inode_dir_add_child (parent_inode, name, inode);
  glick_inode_unref (inode); // We don't return an owned ref, but the one owned by parent_inode->known_children

  return inode;
}

static GlickInode *
try_to_create_child (GlickInodeDir *dir, const char *name)
{
  GlickSlice *slice;
  guint32 inode_num;
  GlickSliceInode *slice_inode;
  char *path;

  if (dir->mount != NULL)
    {
      path = g_build_filename (dir->mount_path, name, NULL);
      slice_inode = glick_mount_lookup_path (dir->mount, path, &slice, &inode_num);
      g_free (path);
      if (slice_inode != NULL)
	return create_child_from_slice_inode (dir, name, slice_inode, slice, inode_num);
    }

  return NULL;
}

typedef void (*CreateFunc)(GlickInodeDir *dir, GlickInode *inode, const char *name, gpointer user_data);

static void
try_to_create_children_for_slice (GlickInodeDir *dir, GlickSlice *slice, CreateFunc create_func, gpointer user_data)
{
  GlickMount *mount = dir->mount;
  guint32 dir_path_hash;
  guint64 dirent, last_dirent, i;
  guint32 inode_num;
  GlickSliceInode *slice_inode;
  GlickInode *new;

  if (mount == NULL)
    return;

  dir_path_hash = djb_hash (dir->mount_path);

  slice_inode = glick_slice_lookup_path (slice, dir->mount_path, dir_path_hash, &inode_num);
  if (slice_inode != NULL && S_ISDIR (GUINT16_FROM_LE (slice_inode->mode)))
    {
      dirent = GUINT64_FROM_LE (slice_inode->offset);
      last_dirent = dirent + GUINT64_FROM_LE (slice_inode->size);
      dirent = MIN (dirent, slice->num_dirs);
      last_dirent = MIN (last_dirent, slice->num_dirs);
      for (i = dirent; i < last_dirent; i++)
	{
	  guint16 entry_inode = GUINT32_FROM_LE (slice->dirs[i].inode);
	  if (entry_inode < slice->num_inodes)
	    {
	      GlickSliceInode *entry_slice_inode = &slice->inodes[entry_inode];
	      const char *name =
		glick_slice_lookup_string (slice, GUINT32_FROM_LE (entry_slice_inode->name));
	      if (name != NULL && g_hash_table_lookup (dir->known_children, name) == NULL)
		{
		  new = create_child_from_slice_inode (dir, name, entry_slice_inode, slice, entry_inode);
		  if (create_func)
		    create_func (dir, new, name, user_data);
		}
	    }
	}
    }
}

static void
try_to_create_children (GlickInodeDir *dir)
{
  GlickMount *mount = dir->mount;
  GList *l;

  if (mount == NULL)
    return;

  for (l = mount->slices; l != NULL; l = l->next)
    try_to_create_children_for_slice (dir, l->data, NULL, NULL);
}


static GlickInodeDir *
find_dir_inode_for_op (fuse_req_t req, fuse_ino_t ino)
{
  GlickInodeDir *parent_inode;

  parent_inode = g_hash_table_lookup (glick_inodes, GINT_TO_POINTER (ino));
  if (parent_inode == NULL)
    {
      __debug__ (("replying with NOENT\n"));
      fuse_reply_err (req, ENOENT);
      return NULL;
    }

  if (parent_inode->base.type != GLICK_INODE_TYPE_DIR)
    {
      __debug__ (("replying with NOTDIR\n"));
      fuse_reply_err (req, ENOTDIR);
      return NULL;
    }

  return parent_inode;
}

static GlickInode *
lookup_or_create_child_inode (GlickInodeDir *parent_inode, const char *name)
{
  GlickInode *child_inode;

  child_inode = g_hash_table_lookup (parent_inode->known_children, name);
  if (child_inode == NULL)
      child_inode = try_to_create_child (parent_inode, name);
  return child_inode;
}

static GlickInode *
find_existing_child_inode_for_op (fuse_req_t req, GlickInodeDir *parent_inode, const char *name)
{
  GlickInode *child_inode;

  child_inode = lookup_or_create_child_inode (parent_inode, name);
  if (child_inode == NULL ||
      glick_inode_is_hidden (child_inode))
    {
      __debug__ (("replying with NOENT\n"));
      fuse_reply_err (req, ENOENT);
      return NULL;
    }

  return child_inode;
}

static gboolean
ensure_no_existing_child_for_op (fuse_req_t req, GlickInodeDir *parent_inode, const char *name, GlickInode **hidden_inode)
{
  GlickInode *child_inode;

  child_inode = lookup_or_create_child_inode (parent_inode, name);
  if (child_inode != NULL &&
      (hidden_inode == NULL || !glick_inode_is_hidden (child_inode)))
    {
      __debug__ (("replying with EXIST\n"));
      fuse_reply_err (req, EEXIST);
      return FALSE;
    }

  if (hidden_inode != NULL)
      *hidden_inode = child_inode;

  return TRUE;
}
static void
glick_fs_lookup (fuse_req_t req, fuse_ino_t parent,
		 const char *name)
{
  struct fuse_entry_param e = { 0 };
  GlickInodeDir *parent_inode;
  GlickInode *child_inode;

  __debug__ (("glick_fs_lookup, parent %x '%s'\n", (int)parent, name));

  e.generation = fuse_generation;
  e.attr_timeout = ATTR_CACHE_TIMEOUT_SEC;
  e.entry_timeout = ENTRY_CACHE_TIMEOUT_SEC;

  parent_inode = find_dir_inode_for_op (req, parent);
  if (parent_inode == NULL)
    return;

  child_inode = find_existing_child_inode_for_op (req, parent_inode, name);
  if (child_inode == NULL)
    return;

  child_inode->kernel_ref_count++;
  e.ino = child_inode->fuse_inode;
  glick_inode_stat (child_inode, &e.attr);
  fuse_reply_entry (req, &e);
}

static void
glick_fs_forget (fuse_req_t req, fuse_ino_t ino, unsigned long nlookup)
{
  GlickInode *inode;

  __debug__(("glick_fs_forget %x %ld\n", (int)ino, nlookup));

  inode = g_hash_table_lookup (glick_inodes, GINT_TO_POINTER (ino));
  if (inode != NULL)
    {
      g_assert (inode->kernel_ref_count >= nlookup);
      inode->kernel_ref_count -= nlookup;
    }

  fuse_reply_none (req);
}

static void
glick_fs_getattr (fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
  struct stat stbuf;
  GlickInode *inode;

  __debug__ (("glick_fs_getattr %x\n", (int)ino));
  (void) fi;

  inode = g_hash_table_lookup (glick_inodes, GINT_TO_POINTER (ino));
  if (inode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  memset (&stbuf, 0, sizeof(stbuf));
  glick_inode_stat (inode, &stbuf);
  fuse_reply_attr (req, &stbuf, ATTR_CACHE_TIMEOUT_SEC);
}

static void
glick_fs_mknod (fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode, dev_t rdev)
{
  struct fuse_entry_param e = {0};
  GlickInodeDir *parent_inode;
  GlickInodeSocket *socket_inode;

  e.generation = fuse_generation;
  e.attr_timeout = ATTR_CACHE_TIMEOUT_SEC;
  e.entry_timeout = ENTRY_CACHE_TIMEOUT_SEC;

  __debug__ (("glick_fs_mknod %x %s %x %x\n", (int)parent, name, mode, (int)rdev));

  parent_inode = find_dir_inode_for_op (req, parent);
  if (parent_inode == NULL)
    return;

  if (S_ISSOCK (mode))
    {
      if (!ensure_no_existing_child_for_op (req, parent_inode, name, NULL))
	return;

      if (parent_inode != glick_root ||
	  strcmp (SOCKET_NAME, name) != 0)
	{
	  fuse_reply_err (req, EPERM);
	  return;
	}

      socket_inode = glick_inode_new_socket ();
      socket_inode->base.kernel_ref_count++;
      glick_inode_own ((GlickInode *)socket_inode);
      glick_inode_dir_add_child (parent_inode, name, (GlickInode *)socket_inode);
      glick_inode_unref ((GlickInode *)socket_inode);

      e.ino = socket_inode->base.fuse_inode;
      glick_inode_stat ((GlickInode *)socket_inode, &e.attr);
      fuse_reply_entry (req, &e);
    }
  else if (S_ISREG (mode))
    {
      GlickInode *hidden_inode;

      if (!ensure_no_existing_child_for_op (req, parent_inode, name, &hidden_inode))
	return;

      if (hidden_inode)
	{
	  /* Allow creation of hidden inodes, this lets us get inotify events... */
	  if (hidden_inode->type == GLICK_INODE_TYPE_SLICE_FILE)
	    {
	      hidden_inode->kernel_ref_count++;
	      glick_inode_unhide (hidden_inode);
	      e.ino = hidden_inode->fuse_inode;
	      glick_inode_stat (hidden_inode, &e.attr);
	      fuse_reply_entry (req, &e);
	    }
	  else
	    fuse_reply_err (req, EPERM);
	}
      else
	{
	  GlickInodeTransient *transient = glick_inode_new_transient ();

	  if (transient == NULL)
	    {
	      fuse_reply_err (req, ENOMEM);
	    }
	  else
	    {
	      transient->base.kernel_ref_count++;
	      glick_inode_dir_add_child (parent_inode, name, (GlickInode *)transient);
	      glick_inode_own ((GlickInode *)transient);
	      glick_inode_unref ((GlickInode *)transient);
	      e.ino = transient->base.fuse_inode;
	      glick_inode_stat ((GlickInode *)transient, &e.attr);
	      fuse_reply_entry (req, &e);
	    }
	}
    }
  else
    fuse_reply_err (req, EPERM);
}

static void
glick_fs_mkdir (fuse_req_t req, fuse_ino_t parent, const char *name,
		mode_t mode)
{
  struct fuse_entry_param e = {0};
  GlickInodeDir *parent_inode;
  GlickInode *hidden_inode;

  e.generation = fuse_generation;
  e.attr_timeout = ATTR_CACHE_TIMEOUT_SEC;
  e.entry_timeout = ENTRY_CACHE_TIMEOUT_SEC;

  __debug__ (("glick_fs_mkdir %x %s %x\n", (int)parent, name, mode));

  parent_inode = find_dir_inode_for_op (req, parent);
  if (parent_inode == NULL)
    return;

  if (!ensure_no_existing_child_for_op (req, parent_inode, name, &hidden_inode))
    return;

  if (hidden_inode)
    {
      /* Allow creation of hidden inodes, this lets us get inotify events... */
      if (hidden_inode->type == GLICK_INODE_TYPE_DIR)
	{
	  hidden_inode->kernel_ref_count++;
	  glick_inode_unhide (hidden_inode);
	  e.ino = hidden_inode->fuse_inode;
	  glick_inode_stat (hidden_inode, &e.attr);
	  fuse_reply_entry (req, &e);
	}
      else
	fuse_reply_err (req, EPERM);
    }
  else
    {
      GlickInodeDir *child;
      child = glick_inode_new_dir ();
      child->base.kernel_ref_count++;
      glick_inode_dir_add_child (parent_inode, name, (GlickInode *)child);
      glick_inode_own ((GlickInode *)child);
      glick_inode_unref ((GlickInode *)child);

      e.ino = child->base.fuse_inode;
      glick_inode_stat (&child->base, &e.attr);
      fuse_reply_entry (req, &e);
    }
}

static void
glick_fs_rmdir (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  GlickInodeDir *parent_inode;
  GlickInode *child;
  GlickInodeDir *child_dir;

  __debug__ (("glick_fs_rmdir %x %s\n", (int)parent, name));

  parent_inode = find_dir_inode_for_op (req, parent);
  if (parent_inode == NULL)
    return;

  child = find_existing_child_inode_for_op (req, parent_inode, name);
  if (child == NULL)
    return;

  if (child->type != GLICK_INODE_TYPE_DIR)
    {
      fuse_reply_err (req, ENOTDIR);
      return;
    }

  child_dir = (GlickInodeDir *)child;
  if ((child_dir->mount &&
       glick_mount_lookup_path (child_dir->mount, child_dir->mount_path, NULL, NULL) != NULL &&
       !glick_inode_is_removable (child)) ||
      glick_inode_is_immutable (child))
    {
      fuse_reply_err (req, EACCES);
      return;
    }

  if (g_hash_table_size (child_dir->known_children) != 0)
    {
      fuse_reply_err (req, ENOTEMPTY);
      return;
    }

  glick_inode_dir_remove_child (parent_inode, name, FALSE);

  fuse_reply_err (req, 0);
}

static void
glick_fs_unlink (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  GlickInodeDir *parent_inode;
  GlickInode *child;

  __debug__ (("glick_fs_unlink %x %s\n", (int)parent, name));

  parent_inode = find_dir_inode_for_op (req, parent);
  if (parent_inode == NULL)
    return;

  child = find_existing_child_inode_for_op (req, parent_inode, name);
  if (child == NULL)
    return;

  if (parent_inode->mount)
    {
      char *path = g_build_filename (parent_inode->mount_path, name, NULL);
      if (glick_mount_lookup_path (parent_inode->mount, path, NULL, NULL) != NULL)
	{
	  fuse_reply_err (req, EACCES);
	  g_free (path);
	  return;
	}
    }

  if (child->type == GLICK_INODE_TYPE_DIR)
    {
      fuse_reply_err (req, EISDIR);
      return;
    }

  if ((child->type != GLICK_INODE_TYPE_TRANSIENT_FILE &&
       child->type != GLICK_INODE_TYPE_TRANSIENT_SYMLINK &&
       !glick_inode_is_removable (child)) ||
      glick_inode_is_immutable (child))
    {
      fuse_reply_err (req, EACCES);
      return;
    }

  glick_inode_dir_remove_child (parent_inode, name, FALSE);
  fuse_reply_err (req, 0);
}

static void
glick_fs_rename (fuse_req_t req, fuse_ino_t parent, const char *name,
		 fuse_ino_t newparent, const char *newname)
{
  GlickInodeDir *parent_inode, *new_parent_inode;
  GlickInode *child, *existing_child;
  char *path;
  GlickSliceInode *inodep;

  parent_inode = find_dir_inode_for_op (req, parent);
  if (parent_inode == NULL)
    return;

  child = find_existing_child_inode_for_op (req, parent_inode, name);
  if (child == NULL)
    return;

  if (glick_inode_is_immutable (child) ||
      !glick_inode_is_owned (child))
    {
      fuse_reply_err (req, EACCES);
      return;
    }

  if (parent_inode->mount != NULL)
    {
      path = g_build_filename (parent_inode->mount_path, name, NULL);
      inodep = glick_mount_lookup_path (parent_inode->mount, path, NULL, NULL);
      g_free (path);
      if (inodep != NULL)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}
    }

  new_parent_inode = find_dir_inode_for_op (req, newparent);
  if (new_parent_inode == NULL)
    return;

  if (new_parent_inode->mount != NULL)
    {
      path = g_build_filename (new_parent_inode->mount_path, newname, NULL);
      inodep = glick_mount_lookup_path (new_parent_inode->mount, path, NULL, NULL);
      g_free (path);
      if (inodep != NULL)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}
    }

  existing_child = lookup_or_create_child_inode (new_parent_inode, newname);
  if (existing_child != NULL)
    {
      if (glick_inode_is_immutable (existing_child) ||
	  !glick_inode_is_owned (existing_child))
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}

      if (existing_child->type == GLICK_INODE_TYPE_DIR)
	{
	  GlickInodeDir *existing_dir = (GlickInodeDir *)existing_child;

	  if (child->type != GLICK_INODE_TYPE_DIR)
	    {
	      fuse_reply_err (req, EISDIR);
	      return;
	    }

	  if (g_hash_table_size (existing_dir->known_children) > 0)
	    {
	      fuse_reply_err (req, ENOTDIR);
	      return;
	    }
	}

      glick_inode_dir_remove_child (new_parent_inode, newname, FALSE);
    }
  glick_inode_dir_add_child (new_parent_inode, newname, child);
  glick_inode_dir_remove_child (parent_inode, name, FALSE);
  fuse_reply_err (req, 0);
}

static void
glick_fs_symlink (fuse_req_t req, const char *link, fuse_ino_t parent,
		  const char *name)
{
  struct fuse_entry_param e = {0};
  GlickInodeDir *parent_inode;
  GlickInode *hidden_inode;

  __debug__ (("glick_fs_symlink %x %s %s\n", (int)parent, name, link));

  e.generation = fuse_generation;
  e.attr_timeout = ATTR_CACHE_TIMEOUT_SEC;
  e.entry_timeout = ENTRY_CACHE_TIMEOUT_SEC;

  parent_inode = find_dir_inode_for_op (req, parent);
  if (parent_inode == NULL)
    return;

  if (!ensure_no_existing_child_for_op (req, parent_inode, name, &hidden_inode))
    return;

  if (hidden_inode)
    {
      /* Allow creation of hidden inodes, this lets us get inotify events... */
      if (hidden_inode->type == GLICK_INODE_TYPE_SLICE_FILE)
	{
	  hidden_inode->kernel_ref_count++;
	  glick_inode_unhide (hidden_inode);
	  e.ino = hidden_inode->fuse_inode;
	  glick_inode_stat (hidden_inode, &e.attr);
	  fuse_reply_entry (req, &e);
	}
      else
	fuse_reply_err (req, EPERM);
    }
  else
    {
      GlickInode *child;
      child = (GlickInode *)glick_inode_new_symlink (link);
      child->kernel_ref_count++;
      glick_inode_dir_add_child (parent_inode, name, child);
      glick_inode_own (child);
      glick_inode_unref (child);

      e.ino = child->fuse_inode;
      glick_inode_stat (child, &e.attr);
      fuse_reply_entry (req, &e);
    }
}

static void
glick_fs_readlink (fuse_req_t req, fuse_ino_t ino)
{
  GlickInode *inode;

  __debug__ (("glick_fs_readlink %x\n", (int)ino));

  inode = g_hash_table_lookup (glick_inodes, GINT_TO_POINTER (ino));
  if (inode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  switch (inode->type) {
  case GLICK_INODE_TYPE_DIR:
  case GLICK_INODE_TYPE_SOCKET:
  case GLICK_INODE_TYPE_TRANSIENT_FILE:
    fuse_reply_err (req, EINVAL);
    break;
  case GLICK_INODE_TYPE_TRANSIENT_SYMLINK:
    {
      GlickInodeSymlink *symlink = (GlickInodeSymlink *)inode;
      fuse_reply_readlink (req, symlink->symlink);
    }
    break;
  case GLICK_INODE_TYPE_SLICE_FILE:
    {
      GlickInodeSliceFile *file = (GlickInodeSliceFile *)inode;
      if (S_ISLNK (inode->mode))
	{
	  const char *lnk = glick_slice_lookup_string (file->slice,
						       GUINT64_FROM_LE (file->slice_inode->offset));
	  if (lnk != NULL)
	    fuse_reply_readlink (req, lnk);
	  else
	    fuse_reply_err (req, EACCES);
	}
	else
	  fuse_reply_err (req, EINVAL);
    }
    break;
  }
}


static void
glick_fs_opendir (fuse_req_t req, fuse_ino_t ino,
		  struct fuse_file_info *fi)
{
  struct dirbuf *b;
  GlickInodeDir *inode;
  GHashTableIter iter;
  gpointer key, value;

  __debug__ (("glick_fs_opendir %x\n", (int)ino));
  fi->fh = 0;

  inode = find_dir_inode_for_op (req, ino);
  if (inode == NULL)
    return;

  b = dirbuf_new ();

  dirbuf_add (req, b, ".", ino);
  if (inode->parent == NULL)
    dirbuf_add (req, b, "..", inode->base.fuse_inode);
  else
    dirbuf_add (req, b, "..", inode->parent->base.fuse_inode);

  try_to_create_children (inode);

  g_hash_table_iter_init (&iter, inode->known_children);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      const char *name = key;
      GlickInode *child = value;

      dirbuf_add (req, b, name, child->fuse_inode);
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
  GlickInode *inode;
  GlickOpenFile *open;

  __debug__ (("glick_fs_open %x\n", (int)ino));

  inode = g_hash_table_lookup (glick_inodes, GINT_TO_POINTER (ino));
  if (inode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  switch (inode->type) {
  case GLICK_INODE_TYPE_DIR:
    fuse_reply_err (req, EISDIR);
    break;
  case GLICK_INODE_TYPE_SOCKET:
  case GLICK_INODE_TYPE_TRANSIENT_SYMLINK:
    fuse_reply_err (req, EACCES);
    break;
  case GLICK_INODE_TYPE_TRANSIENT_FILE:
    {
      GlickInodeTransient *transient = (GlickInodeTransient *)inode;

      open = g_new0 (GlickOpenFile, 1);
      open->start = 0;
      open->end = -1;
      open->flags = fi->flags;
      open->fd = dup (transient->fd);
      fi->fh = (guint64)open;
      fuse_reply_open (req, fi);
    }
    break;
  case GLICK_INODE_TYPE_SLICE_FILE:
    {
      GlickInodeSliceFile *file = (GlickInodeSliceFile *)inode;
      if (S_ISREG (inode->mode))
	{
	  if ((fi->flags & 3) != O_RDONLY)
	    {
	      fuse_reply_err (req, EACCES);
	      return;
	    }

	  open = g_new0 (GlickOpenFile, 1);
	  open->fd = dup (file->slice->fd);
	  open->start = file->slice->data_offset + GUINT64_FROM_LE (file->slice_inode->offset);
	  open->end = open->start + GUINT64_FROM_LE (file->slice_inode->size);
	  open->flags = fi->flags;
	  fi->fh = (guint64)open;
	  fuse_reply_open (req, fi);
	}
      else
	fuse_reply_err (req, EACCES);
    }
    break;
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

  /* TODO: Write in thread */

  res = pwrite (open->fd, buf, size, off);
  if (res >= 0)
    fuse_reply_write (req, res);
  else
    fuse_reply_err (req, errno);
}

static void
glick_fs_setattr (fuse_req_t req, fuse_ino_t ino, struct stat *attr,
		  int to_set, struct fuse_file_info *fi)
{
  GlickInode *inode;
  GlickInodeTransient *transient;
  struct stat res_stat;
  time_t now;
  int res;

  __debug__ (("glick_fs_setattr %x to_set: %x\n", (int)ino, to_set));

  inode = g_hash_table_lookup (glick_inodes, GINT_TO_POINTER (ino));
  if (inode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (to_set & FUSE_SET_ATTR_SIZE)
    {
      switch (inode->type != GLICK_INODE_TYPE_TRANSIENT_FILE)
	{
	  fuse_reply_err (req, EACCES);
	  return;
	}
      transient = (GlickInodeTransient *)inode;

      res = ftruncate (transient->fd, attr->st_size);
      if (res != 0)
	{
	  int errsv = errno;
	  __debug__ (("replying with %d\n", errsv));
	  fuse_reply_err (req, errsv);
	  return;
	}
      to_set &= ~FUSE_SET_ATTR_SIZE;
    }

  now = 0;
  if (to_set & (FUSE_SET_ATTR_ATIME_NOW | FUSE_SET_ATTR_MTIME_NOW))
    now = time(NULL);

  if (to_set & FUSE_SET_ATTR_ATIME)
    {
      if (to_set & FUSE_SET_ATTR_ATIME_NOW)
	inode->atime = now;
      else
	inode->atime = attr->st_atime;
      to_set &= ~(FUSE_SET_ATTR_ATIME|FUSE_SET_ATTR_ATIME_NOW);
    }

  if (to_set & FUSE_SET_ATTR_MTIME)
    {
      if (to_set & FUSE_SET_ATTR_MTIME_NOW)
	inode->mtime = now;
      else
	inode->mtime = attr->st_mtime;
      to_set &= ~(FUSE_SET_ATTR_MTIME|FUSE_SET_ATTR_MTIME_NOW);
    }

  if (to_set != 0)
    {
      __debug__ (("replying with ENOSYS\n"));
      fuse_reply_err (req, ENOSYS);
      return;
    }

  glick_inode_stat (inode, &res_stat);
  __debug__ (("replying with new attrs\n"));
  fuse_reply_attr (req, &res_stat, ATTR_CACHE_TIMEOUT_SEC);
}

static struct
fuse_lowlevel_ops glick_fs_oper = {
  .lookup	= glick_fs_lookup,
  .forget	= glick_fs_forget,
  .getattr	= glick_fs_getattr,
  .opendir	= glick_fs_opendir,
  .readdir	= glick_fs_readdir,
  .releasedir	= glick_fs_releasedir,
  .mknod	= glick_fs_mknod,
  .mkdir	= glick_fs_mkdir,
  .unlink	= glick_fs_unlink,
  .rename	= glick_fs_rename,
  .rmdir	= glick_fs_rmdir,
  .symlink	= glick_fs_symlink,
  .readlink	= glick_fs_readlink,
  .open		= glick_fs_open,
  .release	= glick_fs_release,
  .read		= glick_fs_read,
  .write	= glick_fs_write,
  .setattr	= glick_fs_setattr,
};

/******************** End of fuse implementation ********************/

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

  parent_inode = GUINT32_FROM_LE (inodep->parent_inode);
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
    inode = GUINT32_FROM_LE (slice->hash[hash_bin].inode);
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

GlickSliceInode *
glick_slice_get_inode (GlickSlice *slice, int local)
{
  if (local < slice->num_inodes)
    return &slice->inodes[local];
  return NULL;
}

GlickSliceInode *
glick_mount_lookup_path_except_slice (GlickMount *mount, const char *path, GlickSlice *except_slice,
				      GlickSlice **slice_out, guint32 *inode_num)
{
  GList *l;
  guint32 path_hash;

  path_hash = djb_hash (path);

  for (l = mount->slices; l != NULL; l = l->next)
    {
      GlickSlice *slice = l->data;
      GlickSliceInode *inode;

      if (slice == except_slice)
	continue;

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

GlickSliceInode *
glick_mount_lookup_path (GlickMount *mount, const char *path, GlickSlice **slice_out, guint32 *inode_num)
{
  return glick_mount_lookup_path_except_slice (mount, path, NULL, slice_out, inode_num);

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
  mount->ref_count--;
  if (mount->ref_count == 0)
    {
      mount->mounted = FALSE;

      while (mount->slices != NULL)
	{
	  GlickSlice *slice = mount->slices->data;
	  glick_mount_remove_slice (mount, slice);
	  glick_slice_unref (slice);
	}

      glick_inode_dir_remove_all_children (mount->dir);
      glick_inode_dir_remove_child (glick_root, mount->name, TRUE);
      glick_inode_unref ((GlickInode *)mount->dir);

      glick_mounts = g_list_remove (glick_mounts, mount);

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

  mount = g_new0 (GlickMount, 1);
  mount->ref_count = 1;
  mount->id = next_glick_mount_id++;

  if (name)
    mount->name = g_strdup (name);
  else
    mount->name = g_strdup_printf ("%d", (int)mount->id);

  glick_mounts = g_list_prepend (glick_mounts, mount);

  mount->dir = glick_inode_new_dir ();
  glick_inode_dir_add_child (glick_root, mount->name, (GlickInode *)mount->dir);
  glick_inode_own ((GlickInode *)mount->dir);
  glick_inode_set_immutable ((GlickInode *)mount->dir, TRUE);
  mount->dir->mount = mount;
  mount->dir->mount_path = g_strdup ("/");

  return mount;
}

gboolean
glick_mount_create_dirs (GlickMount *mount, const char *path)
{
  gchar **elements;
  GlickInodeDir *dir;
  int i;

  if (*path != '/')
    return FALSE;
  path++;

  elements = g_strsplit (path, "/", -1);
  dir = mount->dir;

  for (i = 0; elements[i] != NULL; i++)
    {
      GlickInode *child;
      GlickInodeDir *child_dir;

      child = lookup_or_create_child_inode (dir, elements[i]);
      if (child == NULL)
	{
	  child_dir = glick_inode_new_dir ();
	  glick_inode_dir_add_child (dir, elements[i], (GlickInode *)child_dir);
	  glick_inode_own ((GlickInode *)child_dir);
	  glick_inode_unref ((GlickInode *)child_dir);
	}
      else
	{
	  if (child->type != GLICK_INODE_TYPE_DIR)
	    {
	      g_strfreev (elements);
	      return FALSE;
	    }
	  child_dir = (GlickInodeDir *)child;
	}

      dir = child_dir;
    }

  g_strfreev (elements);

  return TRUE;
}

GlickMount *
glick_mount_new_public (void)
{
  GlickMount *mount;
  GList *l;
  int i;

  mount = glick_mount_new ("exports");
  if (mount == NULL)
    return NULL;

  mount->mounted = TRUE;

  for (i = 0; i < G_N_ELEMENTS (builtin_public_triggers); i++)
    mount->triggers = g_list_prepend (mount->triggers, &builtin_public_triggers[i]);

  for (l = mount->triggers; l != NULL; l = l->next)
    {
      GlickTrigger *trigger = l->data;

      if (trigger->flags & GLICK_TRIGGER_FLAGS_CREATE_DIRECTORY)
	{
	  if (!glick_mount_create_dirs (mount, trigger->directory))
	    g_warning ("can't create trigger directory %s\n", trigger->directory);
	}
    }

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
  GlickMount *mount;
  GlickTrigger *trigger;
} TriggerHit;

static gboolean
slice_changed_cb (gpointer user_data)
{
  TriggerHit *hit = user_data;
  GlickMount *mount = hit->mount;
  GlickTrigger *trigger = hit->trigger;
  const char *c;
  char *path;
  GString *str;

  trigger->tag = 0;

  str = g_string_new ("");
  c = trigger->cmdline;
  while (*c != 0)
    {
      if (*c == '%' && *(c+1) != 0)
	{
	  c++;
	  switch (*c)
	    {
	    case '%':
	      g_string_append_c (str, *c);
	      break;
	    case 'd':
	      path = g_build_filename (glick_mountpoint, mount->name, trigger->directory, NULL);
	      g_string_append (str, path);
	      g_free (path);
	      break;
	    }
	}
      else
	g_string_append_c (str, *c);
      c++;
    }

  g_spawn_command_line_async (str->str, NULL);
  if (trigger->flags & GLICK_TRIGGER_FLAGS_BUMP_DIR_MTIME)
    {
      /* TODO: Bump dir inode mtime and invalidate attrs */
    }
  g_string_free (str, TRUE);

  return FALSE;
}

static void
glick_mount_slice_changed (GlickMount *mount, GlickSlice *slice)
{
  GlickSliceInode *inode;
  GList *l;

  for (l = mount->triggers; l != NULL; l = l->next)
    {
      GlickTrigger *trigger = l->data;
      guint32 path_hash;

      /* Skip if already queued */
      if (trigger->tag != 0)
	continue;

      path_hash = djb_hash (trigger->directory);
      inode = glick_slice_lookup_path (slice, trigger->directory, path_hash, NULL);
      if (inode != NULL)
	{
	  TriggerHit *hit = g_new0 (TriggerHit, 1);
	  hit->mount = mount;
	  hit->trigger = trigger;
	  trigger->tag = g_idle_add_full (G_PRIORITY_DEFAULT, slice_changed_cb, hit, (GDestroyNotify)g_free);

	}
    }
}


typedef struct {
  char *path;
  GlickInode *inode;
} ChangedFile;

static void
collect_added_paths_cb (GlickInodeDir *dir,
			GlickInode *inode,
			const char *name,
			gpointer user_data)
{
  GList **added_files = user_data;

  if (S_ISREG (inode->mode) || S_ISDIR (inode->mode) )
    {
      ChangedFile *f = g_new0 (ChangedFile, 1);

      f->path =
	g_build_filename (glick_mountpoint, dir->mount->name, dir->mount_path, name, NULL);
      f->inode = glick_inode_ref (inode);
      glick_inode_hide (inode);

      *added_files = g_list_prepend (*added_files, f);
    }
}

static void
collect_added_paths (GlickInodeDir *dir,
		     GlickSlice *slice,
		     GList **added_files)
{
  GHashTableIter iter;
  gpointer key, value;

  g_hash_table_iter_init (&iter, dir->known_children);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      GlickInode *child = value;

      if (child->type == GLICK_INODE_TYPE_DIR)
	collect_added_paths ((GlickInodeDir *)child, slice, added_files);
    }

  if (dir->base.kernel_ref_count > 0)
    try_to_create_children_for_slice (dir, slice, collect_added_paths_cb, added_files);
}

static void
collect_removed_paths (GlickInodeDir *dir,
		       GlickSlice *slice,
		       GList **removed_files)
{
  GHashTableIter iter;
  gpointer key, value;

  if (dir->base.kernel_ref_count > 0)
    try_to_create_children_for_slice (dir, slice, NULL, NULL);

  g_hash_table_iter_init (&iter, dir->known_children);
  while (g_hash_table_iter_next (&iter, &key, &value))
    {
      const char *name = key;
      GlickInode *child = value;
      guint32 path_hash;

      if (dir->base.kernel_ref_count > 0)
	{
	  GlickSliceInode *inodep, *inodep_mount;
	  char *path;

	  path = g_build_filename (dir->mount_path, name, NULL);
	  path_hash = djb_hash (path);
	  inodep = glick_slice_lookup_path (slice, path, path_hash, NULL);
	  inodep_mount = glick_mount_lookup_path_except_slice (dir->mount, path, slice, NULL, NULL);
	  g_free (path);
	  /* TODO: Also check for non-slice (grand)children of a directory => don't remove */
	  if (inodep != NULL && inodep_mount == NULL)
	    {
	      ChangedFile *f = g_new0 (ChangedFile, 1);

	      f->path =
		g_build_filename (glick_mountpoint, dir->mount->name, dir->mount_path, name, NULL);
	      f->inode = glick_inode_ref (child);
	      glick_inode_set_removable (child, TRUE);

	      *removed_files = g_list_prepend (*removed_files, f);
	    }
	}

      if (child->type == GLICK_INODE_TYPE_DIR)
	collect_removed_paths ((GlickInodeDir *)child, slice, removed_files);
    }

}

typedef struct {
  GlickThreadOp base;
  gboolean remove;
  GList *changed_files;
  GlickMount *mount;
  GlickSlice *slice;
} GlickThreadOpChanges;

static void
changes_op_result (GlickThreadOp *op)
{
  GlickThreadOpChanges *changes = (GlickThreadOpChanges *)op;
  GList *l;

  for (l = changes->changed_files; l != NULL; l = l->next)
    {
      ChangedFile *changed_file = l->data;
      g_free (changed_file->path);
      glick_inode_unhide (changed_file->inode);
      glick_inode_unref (changed_file->inode);
      g_free (changed_file);
    }

  g_list_free (changes->changed_files);

  if (changes->remove)
    glick_mount_real_remove_slice (changes->mount, changes->slice);

  glick_mount_slice_changed (changes->mount, changes->slice);

  glick_mount_unref (changes->mount);
  glick_slice_unref (changes->slice);
}


static void
changes_op_thread (GlickThreadOp *op)
{
  GlickThreadOpChanges *changes = (GlickThreadOpChanges *)op;
  GList *l;

  for (l = changes->changed_files; l != NULL; l = l->next)
    {
      ChangedFile *changed_file = l->data;
      if (changes->remove)
	{
	  if (S_ISDIR (changed_file->inode->mode))
	    {
	      if (rmdir (changed_file->path) == -1)
		perror ("inotify rmdir");
	    }
	  else
	    {
	      if (unlink (changed_file->path) == -1)
		perror ("inotify unlink");
	    }
	}
      else
	{
	  if (S_ISDIR (changed_file->inode->mode))
	    {
	      if (mkdir (changed_file->path, 0755) == -1)
		perror ("inotify mkdir");
	    }
	  else
	    {
	      if (mknod (changed_file->path, S_IFREG | 0755, 0) == -1)
		perror ("inotify mknod");
	    }
	}
    }
}

void
glick_mount_add_slice (GlickMount *mount, GlickSlice *slice)
{
  mount->slices = g_list_prepend (mount->slices, slice);

  if (mount->mounted &&
      (slice->flags & GLICK_SLICE_FLAGS_EXPORT))
    {
      GList *added_files = NULL;
      collect_added_paths (mount->dir,
			   slice,
			   &added_files);

      if (added_files)
	{
	  GlickThreadOpChanges *op;

	  op = g_new0 (GlickThreadOpChanges, 1);
	  op->remove = FALSE;
	  op->changed_files = added_files;
	  op->mount = glick_mount_ref (mount);
	  op->slice = glick_slice_ref (slice);

	  glick_thread_push ((GlickThreadOp *)op,
			     changes_op_thread,
			     changes_op_result);
	}
      else
	glick_mount_slice_changed (mount, slice);
    }
  else
    glick_mount_slice_changed (mount, slice);
}

void
glick_mount_real_remove_slice (GlickMount *mount, GlickSlice *slice)
{
  mount->slices = g_list_remove (mount->slices, slice);
  glick_inode_dir_remove_stale_children (mount->dir);
  glick_mount_slice_changed (mount, slice);
}

void
glick_mount_remove_slice (GlickMount *mount, GlickSlice *slice)
{
  if (mount->mounted &&
      (slice->flags & GLICK_SLICE_FLAGS_EXPORT))
    {
      GList *removed_files = NULL;

      collect_removed_paths (mount->dir,
			     slice,
			     &removed_files);

      if (removed_files)
	{
	  GlickThreadOpChanges *op;

	  op = g_new0 (GlickThreadOpChanges, 1);
	  op->remove = TRUE;
	  op->changed_files = removed_files;
	  op->mount = glick_mount_ref (mount);
	  op->slice = glick_slice_ref (slice);

	  glick_thread_push ((GlickThreadOp *)op,
			     changes_op_thread,
			     changes_op_result);
	}
      else
	glick_mount_real_remove_slice (mount, slice);
    }
  else
    glick_mount_real_remove_slice (mount, slice);
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
glick_public_lookup_by_bundle (const char *bundle_id)
{
  GList *l;

  for (l = glick_publics; l != NULL; l = l->next)
    {
      GlickPublic *public = l->data;
      if (strcmp (public->bundle_id, bundle_id) == 0)
	return public;
    }

  return NULL;
}

GlickPublic *
glick_public_lookup_by_id (guint32 id)
{
  GList *l;

  for (l = glick_publics; l != NULL; l = l->next)
    {
      GlickPublic *public = l->data;
      if (public->id == id)
	return public;
    }

  return NULL;
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
  GlickPublic *public;
  struct stat statbuf;
  GlickInode *symlink;

  int fd = open (filename, O_RDONLY);
  if (fd == -1)
    return NULL;

  if (fstat (fd, &statbuf) != 0)
    return NULL;

  data = map_and_verify_bundle (fd, &header_size);
  if (data == NULL)
    return NULL;

  public = g_new0 (GlickPublic, 1);
  public->id = next_glick_public_id++;
  public->filename = g_strdup (filename);
  public->mtime = statbuf.st_mtime;

  header = (GlickBundleHeader *)data;

  /* TODO: Verify offsets */
  public->bundle_id = g_strndup (data + GUINT32_FROM_LE (header->bundle_id_offset),
				 GUINT32_FROM_LE (header->bundle_id_size));

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

  glick_public_apply_to_mount (public, public_mount);

  symlink = (GlickInode *)glick_inode_new_symlink (filename);
  glick_inode_dir_add_child (glick_bundles_dir, public->bundle_id, symlink);
  glick_inode_own (symlink);
  glick_inode_set_immutable (symlink, TRUE);
  glick_inode_unref (symlink);

  return public;
}

void
glick_public_free (GlickPublic *public)
{
  GList *l;

  glick_publics = g_list_remove (glick_publics, public);

  glick_public_unapply_to_mount (public, public_mount);

  for (l = public->slices; l != NULL; l = l->next)
    {
      GlickSlice *slice = l->data;
      glick_slice_unref (slice);
    }
  g_list_free (public->slices);

  glick_inode_dir_remove_child (glick_bundles_dir, public->bundle_id, TRUE);

  g_free (public->filename);
  g_free (public->bundle_id);
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

  glick_inode_dir_add_child (public_mount->dir, ".bundles", (GlickInode *)glick_bundles_dir);

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


  glick_inodes = g_hash_table_new (g_direct_hash, g_direct_equal);

  glick_root = glick_inode_new_dir ();
  glick_root->base.kernel_ref_count++;
  glick_inode_own ((GlickInode *)glick_root);
  glick_inode_set_immutable ((GlickInode *)glick_root, TRUE);

  glick_bundles_dir = glick_inode_new_dir ();
  glick_inode_own ((GlickInode *)glick_bundles_dir);
  glick_inode_set_immutable ((GlickInode *)glick_bundles_dir, TRUE);

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
