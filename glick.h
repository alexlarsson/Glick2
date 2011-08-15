#include <stdint.h>

typedef struct {
  uint32_t version;
  uint32_t padding;
  uint64_t offset;
} GlickMountRequestMsg;

typedef struct {
  uint32_t result;
  uint32_t padding;
  char name[128];
} GlickMountRequestReply;
