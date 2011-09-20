#include <stdint.h>

typedef struct {
  uint32_t glick_version;
  uint32_t padding;
  uint32_t slice_length; /* doesn't include data */
  uint32_t hash_offset;
  uint32_t hash_shift; /* 1 << hash_shift == num hash entries */
  uint32_t strings_offset;
  uint32_t strings_size;
  uint32_t inodes_offset;
  uint32_t num_inodes;
  uint32_t dirs_offset;
  uint32_t num_dirs;

  uint32_t data_offset;
  uint64_t data_size;
} GlickSliceRoot;

typedef struct {
  /* Hashed by full path */
  uint16_t inode;
}  GlickSliceHash;

typedef struct {
  uint32_t path_hash;
  uint32_t name;
  uint16_t parent_inode;
  uint16_t pad;
  uint32_t mode;
  uint64_t offset; /* data_offset for files, dirs_offset for dirs */
  uint64_t size;   /* n_bytes for files, n_files for dirs */
} GlickSliceInode;

typedef struct {
  uint16_t inode; /* index in inodes */
} GlickSliceDirEntry;

#define INVALID_INODE 0xffff
