#include <glib.h>

typedef struct {
  guint32 glick_version;
  guint32 padding;
  guint32 slice_length; /* doesn't include data */
  guint32 hash_offset;
  guint32 hash_shift; /* 1 << hash_shift == num hash entries */
  guint32 strings_offset;
  guint32 strings_size;
  guint32 inodes_offset;
  guint32 num_inodes;
  guint32 dirs_offset;
  guint32 num_dirs;

  guint32 data_offset;
  guint64 data_size;
} GlickSliceRoot;

typedef struct {
  /* Hashed by full path */
  guint16 inode;
}  GlickSliceHash;

typedef struct {
  guint32 path_hash;
  guint32 name;
  guint16 parent_inode;
  guint16 pad;
  guint32 mode;
  guint64 offset; /* data_offset for files, dirs_offset for dirs */
  guint64 size;   /* n_bytes for files, n_files for dirs */
} GlickSliceInode;

typedef struct {
  guint16 inode; /* index in inodes */
} GlickSliceDirEntry;

#define INVALID_INODE 0xffff
