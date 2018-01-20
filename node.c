#include <stdlib.h>
#include <pthread.h>
#include "node.h"
#include "logging.h"

pthread_mutex_t mutexsum = PTHREAD_MUTEX_INITIALIZER;

btnode* addLink(int key, btnode** node) {
  pthread_mutex_lock(&mutexsum);
  btnode* prev = NULL;
  while (*node) {
    if ((*node)->key == key) {
      logerr("addLink","Reuse fd=%d",key);
      pthread_mutex_unlock(&mutexsum);
      return *node;
    }
    prev = *node;
    node = &(*node)->next;
  }
  *node = calloc(1,sizeof(struct btnode));
  (*node)->key = key;
  (*node)->prev = prev;
  pthread_mutex_unlock(&mutexsum);
  return *node;
}

btnode* findLink(int key, btnode** node) {
  pthread_mutex_lock(&mutexsum);
  while (*node) {
    if ((*node)->key == key) {
      pthread_mutex_unlock(&mutexsum);
      return *node;
    }
    node = &(*node)->next;
  }
  pthread_mutex_unlock(&mutexsum);
  return NULL;
}

void delLink(int key, btnode** node) {
  pthread_mutex_lock(&mutexsum);
  while (*node) {
    if ((*node)->key == key) {
      btnode* me = *node;
      if ((*node)->next) {
        (*node)->next->prev = (*node)->prev;
      }
      if ((*node)->prev) {
        (*node)->prev->next = (*node)->next;
      } else {
        *node = (*node)->next;
      }
      free(me);
      pthread_mutex_unlock(&mutexsum);
      return;
    }
    node = &(*node)->next;
  }
  pthread_mutex_unlock(&mutexsum);
}

