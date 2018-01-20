
#define FUSE_USE_VERSION 26

#include <osxfuse/fuse/fuse.h>
#include "node.h"

struct y_state {
  btnode*       list;
  char          rootdir[PATH_MAX];
  FILE*         logfile;
  unsigned char f_ring[256];
  unsigned char r_ring[256];
  unsigned char offsets[5];
  unsigned char safe_digest[16];
  unsigned char rotor_digest[16];
};

#define Y_STATE ((struct y_state *) fuse_get_context()->private_data)

