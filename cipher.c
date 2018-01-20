#include <stdlib.h>
#include "cipher.h"

void generate_random_rotor(unsigned char* f_ring, unsigned char* r_ring) {
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

void encode_rotor(unsigned char* f_ring, unsigned char *digest) {
  for(int i=0; i<256; i++) {
    f_ring[i] += digest[i&15];
    f_ring[i] += digest[(i+1)&15]*2;
    f_ring[i] += digest[(i+2)&15]*3;
    f_ring[i] += digest[(i+3)&15]*5;
    f_ring[i] += digest[(i+4)&15]*7;
  }
}

void decode_rotor(unsigned char* f_ring, unsigned char *digest) {
  for(int i=0; i<256; i++) {
    f_ring[i] -= digest[i&15];
    f_ring[i] -= digest[(i+1)&15]*2;
    f_ring[i] -= digest[(i+2)&15]*3;
    f_ring[i] -= digest[(i+3)&15]*5;
    f_ring[i] -= digest[(i+4)&15]*7;
  }
}

void derive_reverse_rotor(unsigned char* f_ring, unsigned char* r_ring) {
  for(int j=0; j<256; j++) {
    unsigned char m = f_ring[j];
    r_ring[m] = j;
  }
}

void increment(unsigned char *ix0, unsigned char *ix1, unsigned char *ix2, unsigned char *ix3, unsigned char *ix4) {
  (*ix4)++;
  if ((*ix4)==0) {
    (*ix3)++;
    if ((*ix3)==0) {
      (*ix2)++;
      if ((*ix2)==0) {
        (*ix1)++;
        if ((*ix1)==0) {
          (*ix0)++;
        }
      }
    }
  }
}

void initialise(unsigned char *offsets, uint64_t pos, unsigned char *ix0, unsigned char *ix1, unsigned char *ix2, unsigned char *ix3, unsigned char *ix4) {
  (*ix0) = (offsets[0] + pos/256/256/256/256);
  (*ix1) = (offsets[1] + pos/256/256/256);
  (*ix2) = (offsets[2] + pos/256/256);
  (*ix3) = (offsets[3] + pos/256);
  (*ix4) = (offsets[4] + pos);
}

void encipher(unsigned char *f_ring, unsigned char *offsets, uint64_t pos, unsigned char* data, uint64_t ofs, uint64_t len) {
  unsigned char ix0, ix1, ix2, ix3, ix4;
  initialise(offsets,pos,&ix0,&ix1,&ix2,&ix3,&ix4);
  for(uint64_t ptr=ofs; ptr<(ofs+len); ptr++) {
    unsigned char k4 = ix4 + data[ptr];
    data[ptr] = f_ring[k4];
    unsigned char k3 = ix3 + data[ptr];
    data[ptr] = f_ring[k3];
    unsigned char k2 = ix2 + data[ptr];
    data[ptr] = f_ring[k2];
    unsigned char k1 = ix1 + data[ptr];
    data[ptr] = f_ring[k1];
    unsigned char k0 = ix0 + data[ptr];
    data[ptr] = f_ring[k0];
    increment(&ix0,&ix1,&ix2,&ix3,&ix4);
  }
}

void decipher(unsigned char *r_ring, unsigned char *offsets, uint64_t pos, unsigned char* data, uint64_t ofs, uint64_t len) {
  unsigned char ix0, ix1, ix2, ix3, ix4;
  initialise(offsets,pos,&ix0,&ix1,&ix2,&ix3,&ix4);
  for(uint64_t ptr=ofs; ptr<(ofs+len); ptr++) {
    unsigned char k0 = data[ptr];
    data[ptr] = r_ring[k0] - ix0;
    unsigned char k1 = data[ptr];
    data[ptr] = r_ring[k1] - ix1;
    unsigned char k2 = data[ptr];
    data[ptr] = r_ring[k2] - ix2;
    unsigned char k3 = data[ptr];
    data[ptr] = r_ring[k3] - ix3;
    unsigned char k4 = data[ptr];
    data[ptr] = r_ring[k4] - ix4;
    increment(&ix0,&ix1,&ix2,&ix3,&ix4);
  }
}

