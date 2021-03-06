#include "config.h"

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
  char *full_path;
  char *relative_path;
  struct stat statbuf;
  char *symlink_data;
  SFile *parent;
  GList *children;

  guint32 inode;
  guint32 symlink_offset;
  guint32 name_offset;
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

SFile *
dup_file (SFile *file)
{
  SFile *new;

  new = g_new0 (SFile, 1);

  new->name = g_strdup (file->name);
  new->full_path = g_strdup (file->full_path);
  new->relative_path = g_strdup (file->relative_path);
  new->statbuf = file->statbuf;

  return new;
}

SFile *
split_files (SFile *orig_file, char **split_paths, gboolean *replace_orig)
{
  GList *l, *next, *new_children;
  SFile *orig_child, *new_child, *new_file;
  gboolean replace_child;
  int i;

  for (i = 0; split_paths[i] != NULL; i++)
    {
      char *path;

      path = split_paths[i];
      while (*path == '/')
	path++;

      if (strcmp (path, orig_file->relative_path+1) == 0)
	{
	  *replace_orig = TRUE;
	  return orig_file;
	}
    }

  new_children = NULL;
  l = orig_file->children;
  while (l != NULL)
    {
      orig_child = l->data;
      next = l->next;

      new_child = split_files (orig_child, split_paths, &replace_child);
      if (new_child)
	{
	  new_children = g_list_append (new_children, new_child);
	  if (replace_child)
	    orig_file->children = g_list_remove (orig_file->children, orig_child);
	}

      l = next;
    }

  if (new_children == NULL)
    return NULL;

  new_file = dup_file (orig_file);
  new_file->children = new_children;
  for (l = new_children; l != NULL; l = l->next)
    {
      new_child = l->data;
      new_child->parent = new_file;
    }

  *replace_orig = FALSE;
  return new_file;
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

  inode->mode = GUINT16_TO_LE (file->statbuf.st_mode);
  inode->mtime = GUINT64_TO_LE (file->statbuf.st_mtime);
  if (S_ISDIR (file->statbuf.st_mode)) {
    int n_entries = g_list_length (file->children);
    inode->size = GUINT64_TO_LE (n_entries);
    inode->offset = GUINT64_TO_LE (inode_data->last_dirent);
    for (l = file->children, i = 0; l != NULL; l = l->next, i++) {
      SFile *child = l->data;
      inode_data->dirents[inode_data->last_dirent++].inode = GUINT32_TO_LE (child->inode);
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
  inode_data->hash[bucket].inode = GUINT32_TO_LE (file->inode);
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
  goffset inodes_offset;
  GlickSliceInode *inodes;
  GlickSliceDirEntry *dirents;
  guint64 data_size;
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
  if (n_inodes >= G_MAXUINT32) {
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

  return slice;
}

void
slice_free (Slice *slice)
{
  g_free (slice->strings);
  g_free (slice->hash);
  g_free (slice->inodes);
  g_free (slice->dirents);
  // TODO: Free slice->root
  g_free (slice);
}

gboolean
slice_rewrite_header (Slice *slice, GOutputStream *output, GError **error)
{
  if (!g_seekable_seek (G_SEEKABLE (output), slice->inodes_offset, G_SEEK_SET, NULL, error))
    return FALSE;

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->inodes, sizeof (GlickSliceInode) * slice->n_inodes,
				  NULL, NULL, error))
    return FALSE;

  return TRUE;
}

gboolean
slice_write_header (Slice *slice, GOutputStream *output, GError **error)
{
  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  &slice->header, sizeof (slice->header),
				  NULL, NULL, error))
    return FALSE;

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->hash, sizeof (GlickSliceHash) * slice->n_hashes,
				  NULL, NULL, error))
    return FALSE;

  slice->inodes_offset = g_seekable_tell (G_SEEKABLE (output));
  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->inodes, sizeof (GlickSliceInode) * slice->n_inodes,
				  NULL, NULL, error))
    return FALSE;

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->dirents, sizeof (GlickSliceDirEntry) * slice->n_dirents,
				  NULL, NULL, error))
    return FALSE;

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  slice->strings, slice->strings_size,
				  NULL, NULL, error))
    return FALSE;

  return TRUE;
}

static gssize
copy_data (GInputStream     *source,
	   GOutputStream    *output,
	   GChecksum        *checksum,
	   GCancellable     *cancellable,
	   GError          **error)
{
  gssize n_read, n_written;
  gsize bytes_copied;
  char buffer[8192], *p;
  gboolean res;

  bytes_copied = 0;

  res = TRUE;
  do
    {
      n_read = g_input_stream_read (source, buffer, sizeof (buffer), cancellable, error);
      if (n_read == -1)
	{
	  res = FALSE;
	  break;
	}

      if (n_read == 0)
	break;

      g_checksum_update (checksum, (guchar *)buffer, n_read);

      p = buffer;
      while (n_read > 0)
	{
	  n_written = g_output_stream_write (output, p, n_read, cancellable, error);
	  if (n_written == -1)
	    {
	      res = FALSE;
	      break;
	    }

	  p += n_written;
	  n_read -= n_written;
	  bytes_copied += n_written;
	}

      if (bytes_copied > G_MAXSSIZE)
	bytes_copied = G_MAXSSIZE;
    }
  while (res);

  if (!res)
    error = NULL; /* Ignore further errors */

  if (res)
    return bytes_copied;

  return -1;
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
  GChecksum *checksum;

  if (! S_ISREG (file->statbuf.st_mode))
    return;

  f = g_file_new_for_path (file->full_path);
  error = NULL;
  in = g_file_read (f, NULL, &error);
  g_object_unref (f);
  if (in == NULL)
    {
      g_printerr ("Can't read file %s: %s\n", file->full_path, error->message);
      exit (1);
    }

  checksum = g_checksum_new (G_CHECKSUM_SHA1);

  size = copy_data (G_INPUT_STREAM (in), output, checksum, NULL, &error);
  if (size < 0)
    {
      g_printerr ("Can't read file %s: %s\n", file->full_path, error->message);
      exit (1);
    }
  if (size != file->statbuf.st_size)
    {
      g_printerr ("Wrong file size for %s. Did it change during scan?\n", file->full_path);
      exit (1);
    }

  gsize len = SHA1_CHECKSUM_SIZE;
  g_checksum_get_digest (checksum,
			 data->slice->inodes[file->inode].checksum,
			 &len);
  g_assert (len == SHA1_CHECKSUM_SIZE);

  g_checksum_free (checksum);
  g_input_stream_close (G_INPUT_STREAM (in), NULL, NULL);
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
  char *default_executable;
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
bundle_set_default_executable (Bundle *bundle, const char *exec)
{
  g_free (bundle->default_executable);
  bundle->default_executable = g_strdup (exec);
}

void
bundle_free (Bundle *bundle)
{
  GList *l;
  for (l = bundle->slices; l != NULL; l = l->next)
    slice_free (l->data);

  g_free (bundle->id);
  g_free (bundle->version);
  g_free (bundle->default_executable);

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
  gsize id_offset, version_offset, exec_offset;
  goffset offset, padding;
  char *exec;
  char pad[4096] = {0 };
  GList *l;
  int i;

  output = g_file_create (dest, 0, NULL, error);
  if (output == NULL)
    return FALSE;

  exec = bundle->default_executable;
  if (exec == NULL)
    exec = "";

  header_data_len =
    sizeof (GlickBundleHeader) +
    g_list_length (bundle->slices) * sizeof (GlickSliceRef) +
    strlen (bundle->id) + strlen (bundle->version) + strlen (exec);
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
  exec_offset = version_offset + strlen (bundle->version);

  memcpy (header_data + id_offset, bundle->id, strlen (bundle->id));
  memcpy (header_data + version_offset, bundle->version, strlen (bundle->version));
  memcpy (header_data + exec_offset, exec, strlen (exec));
  header->bundle_id_offset = GUINT32_TO_LE (id_offset);
  header->bundle_id_size = GUINT32_TO_LE (strlen (bundle->id));
  header->bundle_version_offset = GUINT32_TO_LE (version_offset);
  header->bundle_version_size = GUINT32_TO_LE (strlen (bundle->version));
  if (bundle->default_executable != NULL)
    {
      header->exec_offset = GUINT32_TO_LE (exec_offset);
      header->exec_size = GUINT32_TO_LE (strlen (exec));
    }
  header->slices_offset = GUINT32_TO_LE (sizeof (GlickBundleHeader));
  header->num_slices = GUINT32_TO_LE (g_list_length (bundle->slices));

  /* Write out the header, even though its not up-to-date yet, so that
     we get the following data positioned yet, then we seek back and update */
  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  header_data, header_data_len,
				  NULL, NULL, error))
    return FALSE;

  offset = header_data_len;

  /* Write headers */
  for (l = bundle->slices, i = 0; l != NULL; l = l->next, i++)
    {
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
  for (l = bundle->slices, i = 0; l != NULL; l = l->next, i++)
    {
      Slice *slice = l->data;
      ref = &slice_refs[i];

      ref->data_offset = GUINT64_TO_LE (offset);
      ref->data_size = GUINT64_TO_LE (slice->data_size);
      offset += slice->data_size;

      if (!slice_write_data (slice, G_OUTPUT_STREAM (output), error))
	return FALSE;
    }

  /* Seek back to start and rewrite updated header */
  if (!g_seekable_seek (G_SEEKABLE (output), 0, G_SEEK_SET, NULL, error))
    return FALSE;

  if (!g_output_stream_write_all (G_OUTPUT_STREAM (output),
				  header_data, header_data_len,
				  NULL, NULL, error))
    return FALSE;


  for (l = bundle->slices, i = 0; l != NULL; l = l->next, i++)
    {
      Slice *slice = l->data;

      if (!slice_rewrite_header (slice, G_OUTPUT_STREAM (output), error))
	return FALSE;
    }

  if (!g_output_stream_close (G_OUTPUT_STREAM (output), NULL, error))
    {
      g_object_unref (output);
      return FALSE;
    }

  g_object_unref (output);
  return TRUE;
}

#define BUNDLE_GROUP_NAME "Bundle"
#define BUNDLE_KEY_ID "Id"
#define BUNDLE_KEY_VERSION "Version"
#define BUNDLE_KEY_EXEC "Exec"
#define BUNDLE_KEY_EXPORT "Export"

static char *bundle_version;
static char *bundle_id;
static char *default_executable;
static char **exports;

static GOptionEntry entries[] =
{
  { "bundle-id", 'i', 0, G_OPTION_ARG_STRING, &bundle_id, "Bundle Id (e.g org.foobar.MyApp)", "id" },
  { "bundle-version", 'v', 0, G_OPTION_ARG_STRING, &bundle_version, "Bundle Version (e.g 1.0)", "version" },
  { "default-executable", 'e', 0, G_OPTION_ARG_STRING, &default_executable, "Default executable path", "executable" },
  { "export", 'E', 0, G_OPTION_ARG_STRING_ARRAY, &exports, "Export file", "file" },
  { NULL }
};

int
main (int argc, char *argv[])
{
  SFile *root, *exports_root;
  GFile *f;
  Slice *slice;
  Bundle *bundle;
  GError *error;
  GOptionContext *context;

  g_type_init ();

  error = NULL;
  context = g_option_context_new ("DIR FILENAME - create glick bundle");
  g_option_context_add_main_entries (context, entries, "glick");
  if (!g_option_context_parse (context, &argc, &argv, &error))
    {
      g_print ("option parsing failed: %s\n", error->message);
      exit (1);
    }

  if (argc != 3)
    {
      g_printerr ("%s", g_option_context_get_help (context, TRUE, NULL));
      return 1;
    }

  if (bundle_id == NULL)
    {
      g_printerr ("Bundle id required\n");
      return 1;
    }

  if (bundle_version == NULL)
    {
      g_printerr ("Bundle version required\n");
      return 1;
    }

  bundle = bundle_new (bundle_id, bundle_version);

  if (default_executable)
    bundle_set_default_executable (bundle, default_executable);

  root = slurp_files (argv[1], "/", "/");

  exports_root = NULL;
  if (exports != NULL)
    {
      gboolean replace;
      exports_root = split_files (root, exports, &replace);
      if (replace)
	root = NULL;
    }

  slice = slice_new (root);
  bundle_add_slice (bundle, slice);

  if (exports_root)
    {
      slice = slice_new (exports_root);
      slice->flags |= GLICK_SLICE_FLAGS_EXPORT;
      bundle_add_slice (bundle, slice);
    }

  f = g_file_new_for_commandline_arg (argv[2]);

  if (!bundle_write (bundle, f, &error)) {
    g_printerr ("Can't open output: %s\n", error->message);
    return 1;
  }

  g_object_unref (f);

  return 0;
}
