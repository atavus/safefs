
#define FUSE_USE_VERSION 26

#include <osxfuse/fuse/fuse.h>
#include "node.h"

struct y_state {
  btnode*       list;
  char          rootdir[PATH_MAX];
  FILE*         logfile;
  int           endian; // 1 = little endian , 0 = big endian
  unsigned char offsets[8];
  unsigned char safe_digest[16];
  unsigned char rotor_digest[16];
};

#define Y_STATE ((struct y_state *) fuse_get_context()->private_data)

