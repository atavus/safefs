typedef struct btnode {
  int key;
  unsigned char f_ring[256];
  unsigned char r_ring[256];
  struct btnode *next;
  struct btnode *prev;
} btnode;

btnode* addLink(int key, btnode** node);
btnode* findLink(int key, btnode** node);
void delLink(int key, btnode** node);

