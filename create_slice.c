#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>

typedef struct _SFile SFile;

struct _SFile {
  char *name;
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

  res = g_stat (full_path, &file->statbuf);

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
	  if (child != NULL)
	    file->children = g_list_prepend (file->children, child);
	}
      g_dir_close (dir);
    }

  return file;
}

void
visit_breadth_first (SFile *root)
{
  GQueue *queue;
  SFile *file;
  GList *l;

  queue = g_queue_new ();
  g_queue_push_tail (queue, root);

  while ((file = g_queue_pop_head (queue)) != NULL)
    {
      /* Visit file */

      g_print ("%s\n", file->relative_path);

      /* Queue children */
      for (l = file->children; l != NULL; l = l->next)
	{
	  file = l->data;
	  g_queue_push_tail (queue, file);
	}
    }
}

int
main (int argc, char *argv[])
{
  GString *strings;
  SFile *root;

  if (argc != 3) {
    g_printerr ("Usage: create_slice <dir> <filename>\n");
    return 1;
  }

  root = slurp_files (argv[1], "/", "/");

  strings = g_string_new ("");

  visit_breadth_first (root);

  return 0;
}

