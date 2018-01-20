#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "cipher.h"

void check_cipher_accuracy()
{

  fprintf(stderr,"Checking cipher accuracy\n");

  srandomdev();

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char check[65536];
  for(int i=0; i<65536; i++) {
    check[i] = i;
  }

  unsigned char orig[65536];
  memcpy(orig,check,65536);

  unsigned char offsets[5];
  memset(offsets,0,5);

  encipher(f_ring,offsets,0,check,0,65536);
  if (!memcmp(orig,check,65536)) {
    fprintf(stderr,"encipher algorithm broken\n");
    exit(1);
  }

  decipher(r_ring,offsets,0,check,0,65536);
  if (memcmp(orig,check,65536)) {
    fprintf(stderr,"decipher algorithm broken\n");
    exit(1);
  }

}

void check_cipher_histogram() {

  fprintf(stderr,"Checking cipher histogram\n");

  srandomdev();

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char check[65536];
  for(int i=0; i<65536; i++) {
    check[i] = 0;
  }

  unsigned char offsets[5];
  for(int i=0; i<5; i++) {
    offsets[i] = random();
  }

  encipher(f_ring,offsets,0,check,0,65536);

  unsigned long histo[256];
  memset(histo,0,sizeof(histo));
  for(int i=0; i<65536; i++) {
    histo[check[i]]++;
  }
  for(int i=0; i<256; i++) {
    fprintf(stderr,"%03lu ",histo[i]);
    if ((i%16)==15) fprintf(stderr,"\n");
  }

}

void check_cipher_period() {

  fprintf(stderr,"Checking cipher period\n");

  srandomdev();

  unsigned char offsets[5];
  memset(offsets,0,5);

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char initial[1000000];
  memset(initial,'a',sizeof(initial));

  unsigned char check[1000000];
  memset(check,'a',sizeof(check));
  encipher(f_ring,offsets,0,check,0,sizeof(check));

  unsigned int periods = 0;
  unsigned char verify[1000000];
  unsigned int n=16;
  for(unsigned long ofs=0; ofs<8589934592L; ofs+=1000000) {
    memset(verify,'a',sizeof(verify));
    encipher(f_ring,offsets,ofs,verify,0,sizeof(verify));
    for(unsigned int i=n; i<sizeof(verify); i++) {
      int l=0;
      for(unsigned int j=0; j<1024 && (i+j)<sizeof(verify); j++) {
        if (check[j]!=verify[i+j]) break;
        l=j+1;
      }
      if (l>15) {
        fprintf(stderr,"Period %lu of length %d\n",(ofs+i),l);
        periods++;
      }
    }
    decipher(r_ring,offsets,ofs,verify,0,sizeof(verify));
    if (memcmp(verify,initial,1000000)) {
      fprintf(stderr,"decipher algorithm broken on long file at %lu\n",ofs);
      exit(1);
    }
    n=0;
  }
  fprintf(stderr,"%u periods within 8GB found\n",periods);
}

void check_encipher_speed() {

  fprintf(stderr,"Checking encipher speed\n");

  srandomdev();

  unsigned char offsets[5];
  memset(offsets,0,5);

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char initial[1000000];
  memset(initial,'a',sizeof(initial));

  unsigned char check[1000000];
  memset(check,'a',sizeof(check));

  struct timeval stop, start;
  gettimeofday(&start, NULL);
  for(int i=0; i<1024; i++) {
    encipher(f_ring,offsets,0,check,0,sizeof(check));
  }
  gettimeofday(&stop, NULL);
  unsigned long elapsed_usec = (stop.tv_sec - start.tv_sec)*1000000L + (stop.tv_usec - start.tv_usec);
  unsigned long elapsed_sec = elapsed_usec / 1000000L;
  unsigned long mbytes_per_sec = 1000000L * 1024L / elapsed_sec / 1024L / 1024L;
  fprintf(stderr,"%lu Mbytes per second\n",mbytes_per_sec);

}

void check_decipher_speed() {

  fprintf(stderr,"Checking decipher speed\n");

  srandomdev();

  unsigned char offsets[5];
  memset(offsets,0,5);

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char initial[1000000];
  memset(initial,'a',sizeof(initial));

  unsigned char check[1000000];
  memset(check,'a',sizeof(check));

  struct timeval stop, start;
  gettimeofday(&start, NULL);
  for(int i=0; i<1024; i++) {
    decipher(f_ring,offsets,0,check,0,sizeof(check));
  }
  gettimeofday(&stop, NULL);
  unsigned long elapsed_usec = (stop.tv_sec - start.tv_sec)*1000000L + (stop.tv_usec - start.tv_usec);
  unsigned long elapsed_sec = elapsed_usec / 1000000L;
  unsigned long mbytes_per_sec = 1000000L * 1024L / elapsed_sec / 1024L / 1024L;
  fprintf(stderr,"%lu Mbytes per second\n",mbytes_per_sec);

}

int main(int argc, char** argv) {
  check_cipher_accuracy();
  check_cipher_histogram();
  check_encipher_speed();
  check_decipher_speed();
  check_cipher_period();
}

