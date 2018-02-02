#include <stdlib.h>
#include <string.h>
#include "cipher.h"

void generate_random_rotor(unsigned char f_ring[256], unsigned char r_ring[256]) {
  for(int j=0; j<256; j++) {
    f_ring[j] = j;
  }
  for(int j=0; j<256; j++) {
    unsigned char k = random();
    unsigned char f = f_ring[k];
    f_ring[k] = f_ring[j];
    f_ring[j] = f;
    unsigned char l = f_ring[j];
    r_ring[l] = j;
    unsigned char m = f_ring[k];
    r_ring[m] = k;
  }
}

void encode_rotor(unsigned char f_ring[256], unsigned char digest[16]) {
  for(int i=0; i<256; i++) {
    f_ring[i] += digest[i&15];
    f_ring[i] += digest[(i+1)&15]*2;
    f_ring[i] += digest[(i+2)&15]*3;
    f_ring[i] += digest[(i+3)&15]*5;
    f_ring[i] += digest[(i+4)&15]*7;
  }
}

void decode_rotor(unsigned char f_ring[256], unsigned char digest[16]) {
  for(int i=0; i<256; i++) {
    f_ring[i] -= digest[i&15];
    f_ring[i] -= digest[(i+1)&15]*2;
    f_ring[i] -= digest[(i+2)&15]*3;
    f_ring[i] -= digest[(i+3)&15]*5;
    f_ring[i] -= digest[(i+4)&15]*7;
  }
}

void derive_reverse_rotor(unsigned char f_ring[256], unsigned char r_ring[256]) {
  for(int j=0; j<256; j++) {
    unsigned char m = f_ring[j];
    r_ring[m] = j;
  }
}

// assume little endian architecture
void encipher(unsigned char f_ring[256], unsigned char offsets[8], uint64_t pos, unsigned char* data, uint64_t ofs, uint64_t len) {
  uint64_t ptr;
  int i;
  unsigned char k;
  union {
    unsigned char ix[8];
    uint64_t position;
  } advance;
  memcpy(advance.ix,offsets,8);
  advance.position += pos;
  for(ptr=ofs; len>0; ptr++) {
    len--;
    k = data[ptr];
    for(i=0;i<8;i++) {
      k += advance.ix[i];
      k = f_ring[k];
    }
    data[ptr] = k;
    advance.position++;
  }
}

void decipher(unsigned char r_ring[256], unsigned char offsets[8], uint64_t pos, unsigned char* data, uint64_t ofs, uint64_t len) {
  uint64_t ptr;
  int i;
  unsigned char k;
  union {
    unsigned char ix[8];
    uint64_t position;
  } advance;
  memcpy(advance.ix,offsets,8);
  advance.position += pos;
  for(ptr=ofs; len>0; ptr++) {
    len--;
    k = data[ptr];
    for(i=7;i>=0;i--) {
      k = r_ring[k];
      k -= advance.ix[i];
    }
    data[ptr] = k;
    advance.position++;
  }
}

