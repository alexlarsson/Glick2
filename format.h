#include <glib.h>

#define GLICK_MAGIC "\214GLK\r\n\032\n"
#define GLICK_VERSION 1

typedef enum {
  GLICK_SLICE_FLAGS_NONE = 0,
  GLICK_SLICE_FLAGS_EXPORT = 1<<0
} GlickSliceFlags;

typedef struct {
  guint8 glick_magic[8];
  guint32 glick_version;
  guint32 padding;
  guint32 header_size;
  guint32 bundle_id_offset;
  guint32 bundle_id_size;
  guint32 bundle_version_offset;
  guint32 bundle_version_size;
  guint32 slices_offset;
  guint32 num_slices;
} GlickBundleHeader;

typedef struct {
  guint64 header_offset;
  guint64 header_size;
  guint64 data_offset;
  guint64 data_size;
  guint32 flags;
  guint8 checksum[20]; // SHA-1 digest of header + data
} GlickSliceRef;

typedef struct {
  guint32 hash_offset;
  guint32 hash_shift; /* 1 << hash_shift == num hash entries */
  guint32 strings_offset;
  guint32 strings_size;
  guint32 inodes_offset;
  guint32 num_inodes;
  guint32 dirs_offset;
  guint32 num_dirs;
} GlickSliceHeader;

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
