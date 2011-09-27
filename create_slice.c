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
  guint32 inode;
  guint32 name_offset;
  char *full_path;
  char *relative_path;
  SFile *parent;
  struct stat statbuf;
  GList *children;
  char *symlink_data;
  guint32 symlink_offset;
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
  if (S_ISLNK(file->statbuf.st_mode))
    {
      char buffer[4096];
      ssize_t size;
      size = readlink (full_path, buffer, sizeof (buffer));
      if (size < 0)
	file->symlink_data = g_strdup (".");
      else
	file->symlink_data = g_strndup (buffer, size);
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
  guint32 *n_inodes = user_data;
  file->inode = (*n_inodes)++;
}

typedef struct {
  GHashTable *lookup;
  GString *data;
} StringData;

guint32
get_string (StringData *data, const char *str)
{
  gpointer r;
  guint32 offset;

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

  return (guint32) offset;
}

void
collect_file_names (SFile *file, void *user_data)
{
  StringData *string_data = user_data;
  file->name_offset = get_string (string_data, file->name);

  if (S_ISLNK(file->statbuf.st_mode))
    file->symlink_offset = get_string (string_data, file->symlink_data);
}

typedef struct {
  guint32 n_hashes;
  GlickSliceHash *hash;
  GlickSliceInode *inodes;
  GlickSliceDirEntry *dirents;
  guint32 last_dirent;
  guint64 data_offset;
} InodeData;

guint
djb_hash (const void *v)
{
  const signed char *p;
  guint32 h = 5381;

  for (p = v; *p != '\0'; p++)
    h = (h << 5) + h + *p;

  return h;
}

void
collect_inode (SFile *file, void *user_data)
{
  InodeData *inode_data = user_data;
  GlickSliceInode *inode;
  guint32 hash, bucket;
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
  } else if (S_ISLNK (file->statbuf.st_mode)) {
    inode->size = 0;
    inode->offset = file->symlink_offset;
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

static gint
find_closest_shift (gint n)
{
  gint i;

  for (i = 0; n; i++)
    n >>= 1;

  return i;
}

typedef struct {
  guint32 flags;
  guint32 size;
  GlickSliceHeader header;
  guint32 n_inodes;
  guint32 hash_shift;
  guint32 n_hashes;
  guint32 n_dirents;
  char *strings;
  guint32 strings_size;
  GlickSliceHash *hash;
  GlickSliceInode *inodes;
  GlickSliceDirEntry *dirents;
  guint64 data_size;
  GChecksum *checksum;
  SFile *root;
} Slice;


Slice *
slice_new (SFile *root)
{
  guint32 n_inodes;
  guint32 n_hashes;
  guint32 hash_shift;
  StringData string_data;
  InodeData inode_data;
  Slice *slice;
  guint32 hash_size, inodes_size, dirents_size;

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

  slice = g_new0 (Slice, 1);

  slice->root = root;
  slice->size = sizeof (GlickSliceHeader);

  slice->n_hashes = n_hashes;
  slice->hash_shift = hash_shift;
  slice->hash = inode_data.hash;
  slice->header.hash_offset = GUINT32_TO_LE (slice->size);
  slice->header.hash_shift = GUINT32_TO_LE (hash_shift);
  hash_size = sizeof (GlickSliceHash) * n_hashes;
  slice->size += hash_size;

  slice->n_inodes = n_inodes;
  slice->inodes = inode_data.inodes;
  slice->header.inodes_offset = GUINT32_TO_LE (slice->size);
  slice->header.num_inodes = GUINT32_TO_LE (n_inodes);
  inodes_size = sizeof (GlickSliceInode) * n_inodes;
  slice->size += inodes_size;

  slice->dirents = inode_data.dirents;
  slice->n_dirents = inode_data.last_dirent;
  slice->header.dirs_offset = GUINT32_TO_LE (slice->size);
  slice->header.num_dirs = GUINT32_TO_LE (inode_data.last_dirent);
  dirents_size = sizeof (GlickSliceDirEntry) * inode_data.last_dirent;
  slice->size += dirents_size;

  slice->strings_size = string_data.data->len;
  slice->strings = g_string_free (string_data.data, FALSE);
  slice->header.strings_offset = GUINT32_TO_LE (slice->size);
  slice->header.strings_size = GUINT32_TO_LE (slice->strings_size);
  slice->size += slice->strings_size;

  g_hash_table_destroy (string_data.lookup);

  slice->data_size = inode_data.data_offset;

  slice->checksum = g_checksum_new (G_CHECKSUM_SHA1);

  g_checksum_update (slice->checksum, (guchar *)&slice->header, sizeof (GlickSliceHeader));
  g_checksum_update (slice->checksum, (guchar *)slice->hash, hash_size);
  g_checksum_update (slice->checksum, (guchar *)slice->inodes, inodes_size);
  g_checksum_update (slice->checksum, (guchar *)slice->dirents, dirents_size);
  g_checksum_update (slice->checksum, (guchar *)slice->strings, slice->strings_size);

  return slice;
}

void
slice_free (Slice *slice)
{
  g_free (slice->strings);
  g_free (slice->hash);
  g_free (slice->inodes);
  g_free (slice->dirents);
  g_checksum_free (slice->checksum);
  // TODO: Free slice->root
  g_free (slice);
}

gboolean
slice_write_header (Slice *slice, GOutputStream *output, GError **error)
{
  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  &slice->header, sizeof (slice->header),
				  NULL, NULL, error)) {
    return FALSE;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->hash, sizeof (GlickSliceHash) * slice->n_hashes,
				  NULL, NULL, error)) {
    return FALSE;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->inodes, sizeof (GlickSliceInode) * slice->n_inodes,
				  NULL, NULL, error)) {
    return FALSE;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->dirents, sizeof (GlickSliceDirEntry) * slice->n_dirents,
				  NULL, NULL, error)) {
    return FALSE;
  }

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->strings, slice->strings_size,
				  NULL, NULL, error)) {
    return FALSE;
  }

  return TRUE;
}

struct CollectData {
  GOutputStream *output;
  Slice *slice;
  GError *error;
};

void
collect_data (SFile *file, void *user_data)
{
  struct CollectData *data = user_data;
  GOutputStream *output = data->output;
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
  // TODO: Update checksum
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

gboolean
slice_write_data (Slice *slice, GOutputStream *output, GError **error)
{
  struct CollectData data;
  data.output = output;
  data.slice = slice;
  data.error = NULL;
  // TODO: Error checking
  visit_depth_first (slice->root, collect_data, &data);
  return TRUE;
}


typedef struct {
  char *id;
  char *version;
  GList *slices;
} Bundle;


Bundle *
bundle_new (char *id, char *version)
{
  Bundle *bundle;

  bundle = g_new0 (Bundle, 1);
  bundle->id = g_strdup (id);
  bundle->version = g_strdup (version);

  return bundle;
}

void
bundle_add_slice (Bundle *bundle, Slice *slice)
{
  bundle->slices = g_list_append (bundle->slices, slice);
}

void
bundle_free (Bundle *bundle)
{
  GList *l;
  for (l = bundle->slices; l != NULL; l = l->next)
    slice_free (l->data);

  g_free (bundle);
}

gboolean
bundle_write (Bundle *bundle, GFile *dest, GError **error)
{
  GFileOutputStream *output;
  char *header_data;
  gsize header_data_len;
  GlickBundleHeader *header;
  GlickSliceRef *slice_refs, *ref;
  gsize id_offset;
  gsize version_offset;
  goffset offset, padding;;
  char pad[4096] = {0 };
  GList *l;
  int i;

  output = g_file_create (dest, 0, NULL, error);
  if (output == NULL)
    return FALSE;

  header_data_len =
    sizeof (GlickBundleHeader) +
    g_list_length (bundle->slices) * sizeof (GlickSliceRef) +
    strlen (bundle->id) + strlen (bundle->version);
  header_data = g_malloc0 (header_data_len);
  header = (GlickBundleHeader *)header_data;
  slice_refs = (GlickSliceRef *)(header_data + sizeof (GlickBundleHeader));

  memcpy (header->glick_magic, GLICK_MAGIC, 8);
  header->glick_version = GUINT32_TO_LE (GLICK_VERSION);
  header->header_size = GUINT32_TO_LE (header_data_len);
  id_offset =
    sizeof (GlickBundleHeader) +
    g_list_length (bundle->slices) * sizeof (GlickSliceRef);
  version_offset = id_offset + strlen (bundle->id);
  memcpy (header_data + id_offset, bundle->id, strlen (bundle->id));
  memcpy (header_data + version_offset, bundle->version, strlen (bundle->version));
  header->bundle_id_offset = GUINT32_TO_LE (id_offset);
  header->bundle_id_size = GUINT32_TO_LE (strlen (bundle->id));
  header->bundle_version_offset = GUINT32_TO_LE (version_offset);
  header->bundle_version_size = GUINT32_TO_LE (strlen (bundle->version));
  header->slices_offset = GUINT32_TO_LE (sizeof (GlickBundleHeader));
  header->num_slices = GUINT32_TO_LE (g_list_length (bundle->slices));

  /* Write out the header, even though its not up-to-date yet, so that
     we get the following data positioned yet, then we seek back and update */
  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  header_data, header_data_len,
				  NULL, NULL, error)) {
    return FALSE;
  }

  offset = header_data_len;

  /* Write headers */
  for (l = bundle->slices, i = 0; l != NULL; l = l->next, i++) {
    Slice *slice = l->data;
    ref = &slice_refs[i];

    // Round up to even page for next header
    padding = offset % 4096;
    if (padding != 0)
      padding = 4096-padding;
    offset += padding;
    if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				    pad, padding,
				    NULL, NULL, error))
      return FALSE;

    ref->flags = GUINT32_TO_LE (slice->flags);
    ref->header_offset = GUINT64_TO_LE (offset);
    ref->header_size = GUINT64_TO_LE (slice->size);
    offset += slice->size;

    if (!slice_write_header (slice, G_OUTPUT_STREAM (output), error))
      return FALSE;
  }

  /* Write data */
  for (l = bundle->slices, i = 0; l != NULL; l = l->next, i++) {
    Slice *slice = l->data;
    ref = &slice_refs[i];

    ref->data_offset = GUINT64_TO_LE (offset);
    ref->data_size = GUINT64_TO_LE (slice->data_size);
    offset += slice->data_size;

    if (!slice_write_data (slice, G_OUTPUT_STREAM (output), error))
      return FALSE;

    /* TODO: Update ref->checksum */
  }

  /* Seek back to start and rewrite updated header */
  if (!g_seekable_seek (G_SEEKABLE (output), 0, G_SEEK_SET, NULL, error)) {
    return FALSE;
  }
  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  header_data, header_data_len,
				  NULL, NULL, error)) {
    return FALSE;
  }

  if (!g_output_stream_close (G_OUTPUT_STREAM (output), NULL, error)) {
    g_object_unref (output);
    return FALSE;
  }

  g_object_unref (output);
  return TRUE;
}

int
main (int argc, char *argv[])
{
  SFile *root;
  GFile *f;
  Slice *slice;
  Bundle *bundle;
  GError *error;

  g_type_init ();

  if (argc != 3) {
    g_printerr ("Usage: create_slice <dir> <filename>\n");
    return 1;
  }

  root = slurp_files (argv[1], "/", "/");

  slice = slice_new (root);
  bundle = bundle_new ("org.gnome.Test", "1.0");
  bundle_add_slice (bundle, slice);

  f = g_file_new_for_commandline_arg (argv[2]);

  error = NULL;
  if (!bundle_write (bundle, f, &error)) {
    g_printerr ("Can't open output: %s\n", error->message);
    return 1;
  }

  g_object_unref (f);

  return 0;
}
