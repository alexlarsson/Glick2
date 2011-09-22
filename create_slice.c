#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <gio/gio.h>
#include "format.h"

typedef struct _SFile SFile;

struct _SFile {
  char *name;
  uint32_t inode;
  uint32_t name_offset;
  char *full_path;
  char *relative_path;
  SFile *parent;
  struct stat statbuf;
  GList *children;
};

SFile *
slurp_files (const char *full_path, const char *relative_path, const char *name)
{
  const char *child_name;
  char *child_path, *child_relative_path;
  int res;
  SFile *file, *child;
  GDir *dir;

  file = g_new0 (SFile, 1);

  res = lstat (full_path, &file->statbuf);

  if (res != 0)
    {
      g_free (file);
      return NULL;
    }

  file->name = g_strdup (name);
  file->full_path = g_strdup (full_path);
  file->relative_path = g_strdup (relative_path);

  if (S_ISDIR (file->statbuf.st_mode) &&
      (dir = g_dir_open (full_path, 0, NULL)) != NULL)
    {
      while ((child_name = g_dir_read_name (dir)) != NULL)
	{
	  child_path = g_build_filename (full_path, child_name, NULL);
	  child_relative_path = g_build_filename (relative_path, child_name, NULL);
	  child = slurp_files (child_path, child_relative_path, child_name);
	  g_free (child_relative_path);
	  g_free (child_path);
	  if (child != NULL) {
	    child->parent = file;
	    file->children = g_list_prepend (file->children, child);
	  }
	}
      g_dir_close (dir);
    }

  return file;
}

typedef void FileVisitorFunc (SFile *file, void *user_data);

void
visit_breadth_first (SFile *root, FileVisitorFunc visitor, void *user_data)
{
  GQueue *queue;
  SFile *file;
  GList *l;

  queue = g_queue_new ();
  g_queue_push_tail (queue, root);

  while ((file = g_queue_pop_head (queue)) != NULL)
    {
      /* Visit file */

      visitor (file, user_data);

      /* Queue children */
      for (l = file->children; l != NULL; l = l->next)
	{
	  file = l->data;
	  g_queue_push_tail (queue, file);
	}
    }
}

void
visit_depth_first (SFile *root, FileVisitorFunc visitor, void *user_data)
{
  GQueue *queue;
  SFile *file;
  GList *l;

  queue = g_queue_new ();
  g_queue_push_tail (queue, root);

  while ((file = g_queue_pop_head (queue)) != NULL)
    {
      /* Visit file */

      visitor (file, user_data);

      /* Queue children */
      for (l = file->children; l != NULL; l = l->next)
	{
	  file = l->data;
	  g_queue_push_head (queue, file);
	}
    }
}

void assign_inode (SFile *file, void *user_data)
{
  uint32_t *n_inodes = user_data;
  file->inode = (*n_inodes)++;
}

typedef struct {
  GHashTable *lookup;
  GString *data;
} StringData;

uint32_t
get_string (StringData *data, const char *str)
{
  gpointer r;
  uint32_t offset;

  r = g_hash_table_lookup (data->lookup, str);
  if (r != NULL)
    return GPOINTER_TO_UINT (r);

  if (data->data->len > G_MAXUINT32 - strlen (str) - 1) {
    fprintf (stderr, "To much strings\n");
    exit (1);
  }

  offset = data->data->len;
  g_string_append_len (data->data, str, strlen (str) + 1);

  g_hash_table_insert (data->lookup, g_strdup (str), GUINT_TO_POINTER (offset));

  return (uint32_t) offset;
}

void
collect_file_names (SFile *file, void *user_data)
{
  StringData *string_data = user_data;
  file->name_offset = get_string (string_data, file->name);
}

typedef struct {
  uint32_t n_hashes;
  GlickSliceHash *hash;
  GlickSliceInode *inodes;
  GlickSliceDirEntry *dirents;
  uint32_t last_dirent;
  uint64_t data_offset;
} InodeData;

guint
djb_hash (const void *v)
{
  const signed char *p;
  uint32_t h = 5381;

  for (p = v; *p != '\0'; p++)
    h = (h << 5) + h + *p;

  return h;
}

void
collect_inode (SFile *file, void *user_data)
{
  InodeData *inode_data = user_data;
  GlickSliceInode *inode;
  uint32_t hash, bucket;
  GList *l;
  int i;
  int step;

  hash = djb_hash (file->relative_path);
  inode = &inode_data->inodes[file->inode];

  inode->path_hash = GUINT32_TO_LE (hash);
  inode->name = GUINT32_TO_LE (file->name_offset);
  if (file->parent != NULL)
    inode->parent_inode = file->parent->inode;
  else
    inode->parent_inode = file->inode;

  inode->mode = GUINT32_TO_LE (file->statbuf.st_mode);
  if (S_ISDIR (file->statbuf.st_mode)) {
    int n_entries = g_list_length (file->children);
    inode->size = GUINT64_TO_LE (n_entries);
    inode->offset = GUINT64_TO_LE (inode_data->last_dirent);
    for (l = file->children, i = 0; l != NULL; l = l->next, i++) {
      SFile *child = l->data;
      inode_data->dirents[inode_data->last_dirent++].inode = GUINT16_TO_LE (child->inode);
    }
  } else if (S_ISREG (file->statbuf.st_mode)) {
    inode->size = GUINT32_TO_LE (file->statbuf.st_size);
    inode->offset = GUINT64_TO_LE (inode_data->data_offset);
    inode_data->data_offset += file->statbuf.st_size;
  } else {
    fprintf (stderr, "Unsupported mode for %s\n", file->relative_path);
    inode->size = 0;
    inode->offset = 0;
  }

  bucket = hash % inode_data->n_hashes;
  step = 1;
  while (inode_data->hash[bucket].inode != INVALID_INODE) {
    bucket = (bucket + step) % inode_data->n_hashes;
    step++;
  }
  inode_data->hash[bucket].inode = GUINT16_TO_LE (file->inode);
}

void
collect_data (SFile *file, void *user_data)
{
  GOutputStream *output = G_OUTPUT_STREAM (user_data);
  gssize size;
  GFile *f;
  GError *error;
  GFileInputStream *in;

  if (! S_ISREG (file->statbuf.st_mode))
    return;

  f = g_file_new_for_path (file->full_path);
  error = NULL;
  in = g_file_read (f, NULL, &error);
  g_object_unref (f);
  if (in == NULL) {
    g_printerr ("Can't read file %s: %s\n", file->full_path, error->message);
    exit (1);
  }
  size = g_output_stream_splice (output, G_INPUT_STREAM (in),
				 G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE, NULL, &error);
  if (size < 0) {
    g_printerr ("Can't read file %s: %s\n", file->full_path, error->message);
    exit (1);
  }
  if (size != file->statbuf.st_size) {
    g_printerr ("Wrong fie size for %s. Did it change during scan?\n", file->full_path);
    exit (1);
  }
  g_object_unref (in);
}

static gint
find_closest_shift (gint n)
{
  gint i;

  for (i = 0; n; i++)
    n >>= 1;

  return i;
}


int
main (int argc, char *argv[])
{
  SFile *root;
  uint32_t n_inodes;
  uint32_t n_hashes;
  uint32_t hash_shift;
  StringData string_data;
  InodeData inode_data;
  GlickSliceRoot slice_root = { 0 };
  size_t offset, padding;
  GFile *f;
  GFileOutputStream *output;
  GError *error;
  char pad[4096] = {0 };

  g_type_init ();

  if (argc != 3) {
    g_printerr ("Usage: create_slice <dir> <filename>\n");
    return 1;
  }

  root = slurp_files (argv[1], "/", "/");

  n_inodes = 0;
  visit_depth_first (root, assign_inode, &n_inodes);
  if (n_inodes >= G_MAXUINT16) {
    fprintf (stderr, "To many inodes\n");
    exit (1);
  }

  string_data.lookup = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  string_data.data = g_string_new ("");

  visit_depth_first (root, collect_file_names, &string_data);

  hash_shift = find_closest_shift (n_inodes * 2);
  n_hashes = 1 << hash_shift;
  inode_data.n_hashes = n_hashes;
  inode_data.hash = g_new (GlickSliceHash, n_hashes);
  memset (inode_data.hash, 0xff, sizeof (GlickSliceHash) * n_hashes);
  inode_data.inodes = g_new0 (GlickSliceInode, n_inodes);
  /* Each non-leaf inode has to be in some dirent, plus termination. so max n_inodes */
  inode_data.dirents = g_new0 (GlickSliceDirEntry, n_inodes);
  inode_data.last_dirent = 0;
  inode_data.data_offset = 0;

  visit_depth_first (root, collect_inode, &inode_data);

  slice_root.glick_version = 0;

  offset = sizeof (slice_root);

  slice_root.hash_offset = GUINT32_TO_LE (offset);
  slice_root.hash_shift = GUINT32_TO_LE (hash_shift);
  offset += sizeof (GlickSliceHash) * n_hashes;

  slice_root.inodes_offset = GUINT32_TO_LE (offset);
  slice_root.num_inodes = GUINT32_TO_LE (n_inodes);
  offset += sizeof (GlickSliceInode) * n_inodes;

  slice_root.dirs_offset = GUINT32_TO_LE (offset);
  slice_root.num_dirs = GUINT32_TO_LE (inode_data.last_dirent);
  offset += sizeof (GlickSliceDirEntry) * inode_data.last_dirent;

  slice_root.strings_offset = GUINT32_TO_LE (offset);
  slice_root.strings_size = GUINT32_TO_LE (string_data.data->len);
  offset += string_data.data->len;

  // Round up to even page
  padding = offset % 4096;
  offset += padding;

  slice_root.data_offset = GUINT32_TO_LE (offset);
  slice_root.data_size = GUINT64_TO_LE (inode_data.data_offset);

  slice_root.slice_length = GUINT32_TO_LE (offset);

  f = g_file_new_for_commandline_arg (argv[2]);

  error = NULL;
  output = g_file_create (f, 0, NULL, &error);
  g_object_unref (f);
  if (output == NULL) {
    g_printerr ("Can't open output: %s\n", error->message);
    return 1;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  &slice_root, sizeof (slice_root),
				  NULL, NULL, &error)) {
    g_printerr ("Can't write output: %s\n", error->message);
    return 1;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  inode_data.hash, sizeof (GlickSliceHash) * n_hashes,
				  NULL, NULL, &error)) {
    g_printerr ("Can't write output: %s\n", error->message);
    return 1;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  inode_data.inodes, sizeof (GlickSliceInode) * n_inodes,
				  NULL, NULL, &error)) {
    g_printerr ("Can't write output: %s\n", error->message);
    return 1;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  inode_data.dirents, sizeof (GlickSliceDirEntry) * inode_data.last_dirent,
				  NULL, NULL, &error)) {
    g_printerr ("Can't write output: %s\n", error->message);
    return 1;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  string_data.data->str, string_data.data->len,
				  NULL, NULL, &error)) {
    g_printerr ("Can't write output: %s\n", error->message);
    return 1;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  pad, padding,
				  NULL, NULL, &error)) {
    g_printerr ("Can't write output: %s\n", error->message);
    return 1;
  }

  visit_depth_first (root, collect_data, output);

  if (!g_output_stream_close (G_OUTPUT_STREAM (output), NULL, &error)) {
    g_printerr ("Can't write output: %s\n", error->message);
    return 1;
  }
  g_object_unref (output);

  return 0;
}
