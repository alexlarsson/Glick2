#include <glib.h>

typedef struct {
  guint32 version;
  guint32 padding;
  guint64 offset;
} GlickMountRequestMsg;

typedef struct {
  guint32 result;
  guint32 padding;
  char name[128];
} GlickMountRequestReply;
