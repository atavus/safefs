#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "cipher.h"

void check_cipher_accuracy()
{

  fprintf(stderr,"\nChecking cipher accuracy\n");

  srandomdev();

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char orig[65536];
  for(int i=0; i<65536; i++) {
    orig[i] = i;
  }

  unsigned char check[65536];
  memcpy(check,orig,65536);

  unsigned char offsets[8];
  offsets[0] = 0xdb;
  offsets[1] = 0xea;
  offsets[2] = 0xf9;
  offsets[3] = 0x08;
  offsets[4] = 0x17;
  offsets[5] = 0x17;
  offsets[6] = 0x17;
  offsets[7] = 0x17;

  int endian = determine_endianness(offsets);
  if (endian==0) fprintf(stderr,"Big endian\n");
  else fprintf(stderr,"Little endian\n");

  encipher(f_ring,offsets,397312,check,0,65536,endian,8);
  if (!memcmp(orig,check,65536)) {
    fprintf(stderr,"encipher algorithm broken\n");
    exit(1);
  }

  decipher(r_ring,offsets,397312,check,0,61440,endian,8);
  decipher(r_ring,offsets,458752,check,61440,4096,endian,8);

  if (memcmp(orig,check,65536)) {
    fprintf(stderr,"decipher algorithm broken\n");
    exit(1);
  }

}

void check_cipher_histogram() {

  fprintf(stderr,"\nChecking cipher histogram\n");

  srandomdev();

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char check[65536];
  for(int i=0; i<65536; i++) {
    check[i] = 0;
  }

  unsigned char offsets[8];
  for(int i=0; i<8; i++) {
    offsets[i] = random();
  }

  int endian = determine_endianness(offsets);

  encipher(f_ring,offsets,0,check,0,65536,endian,8);

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

void check_cipher_distribution() {

  fprintf(stderr,"\nChecking cipher distribution\n");

  srandomdev();

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);


  unsigned char offsets[8];
  for(int i=0; i<8; i++) {
    offsets[i] = random();
  }

  int endian = determine_endianness(offsets);

  unsigned char check[2][256];
  for(int pos=0; pos<2; pos++) {
    for(int val=0; val<256; val++) {
      check[pos][val] = val;
      encipher(f_ring,offsets,pos,&check[pos][val],0,1,endian,3);
    }
    fprintf(stderr,"   ");
    for(int i=0; i<16; i++) {
      fprintf(stderr,"%02x ",i);
      if ((i%16)==15) fprintf(stderr,"\n");
    }
    for(int i=0; i<256; i++) {
      if ((i%16)==0) fprintf(stderr,"%02x ",i);
      fprintf(stderr,"%02x ",check[pos][i]);
      if ((i%16)==15) fprintf(stderr,"\n");
    }
    fprintf(stderr,"\n");
  }

  int t=0;
  for(int i=0; i<256; i++) {
    for(int j=0; j<256; j++) {
      int l=0;
      for(int k=0; k<256; k++) {
        if (check[0][(i+k)%256]!=check[1][(j+k)%256]) break;
        l++;
      }
      if (l>2) {
        fprintf(stderr,"Sequence repeated at %02x and %02x for %d\n",i,j,l);
        t++;
      }
    }
  }
  fprintf(stderr,"%d sequences repeated\n",t);

}

void check_cipher_period() {

  fprintf(stderr,"\nChecking cipher period\n");

  srandomdev();

  unsigned char offsets[8];
  memset(offsets,0,8);

  int endian = determine_endianness(offsets);

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char initial[1000000];
  memset(initial,'a',sizeof(initial));

  unsigned char check[1000000];
  memset(check,'a',sizeof(check));
  encipher(f_ring,offsets,0,check,0,sizeof(check),endian,5);

  unsigned int periods = 0;
  unsigned char verify[1000000];
  unsigned int n=1;
  for(unsigned long ofs=0; ofs<8589934592L; ofs+=1000000) {
    memset(verify,'a',sizeof(verify));
    encipher(f_ring,offsets,ofs,verify,0,sizeof(verify),endian,5);
    for(unsigned int i=n; i<sizeof(verify); i++) {
      int l=0;
      for(unsigned int j=0; j<65536 && (i+j)<sizeof(verify); j++) {
        if (check[j]!=verify[i+j]) break;
        l=j+1;
      }
      if (l>255) {
        fprintf(stderr,"Period %lu [%lx] of length %d\n",(ofs+i),(ofs+i),l);
        periods++;
      }
    }
    n=0;
  }
  fprintf(stderr,"%u periods within 8GB found\n",periods);
}

void check_encipher_speed() {

  fprintf(stderr,"\nChecking encipher speed\n");

  srandomdev();

  unsigned char offsets[8];
  memset(offsets,0,8);

  int endian = determine_endianness(offsets);

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char initial[1000000];
  memset(initial,'a',sizeof(initial));

  unsigned char check[1000000];
  memset(check,'a',sizeof(check));

  int rounds[3];
  rounds[0] = 3;
  rounds[1] = 5;
  rounds[2] = 8;
  for(int r=0; r<3; r++) {
    struct timeval stop, start;
    gettimeofday(&start, NULL);
    for(int i=0; i<1024; i++) {
      encipher(f_ring,offsets,0,check,0,sizeof(check),endian,rounds[r]);
    }
    gettimeofday(&stop, NULL);
    unsigned long elapsed_usec = (stop.tv_sec - start.tv_sec)*1000000L + (stop.tv_usec - start.tv_usec);
    unsigned long elapsed_sec = elapsed_usec / 1000000L;
    unsigned long mbytes_per_sec = 1000000L * 1024L / elapsed_sec / 1024L / 1024L;
    fprintf(stderr,"%lu Mbytes per second for %d rounds\n",mbytes_per_sec,rounds[r]);
  }

}

void check_decipher_speed() {

  fprintf(stderr,"\nChecking decipher speed\n");

  srandomdev();

  unsigned char offsets[8];
  memset(offsets,0,8);

  int endian = determine_endianness(offsets);

  unsigned char f_ring[256];
  unsigned char r_ring[256];
  generate_random_rotor(f_ring,r_ring);

  unsigned char initial[1000000];
  memset(initial,'a',sizeof(initial));

  unsigned char check[1000000];
  memset(check,'a',sizeof(check));

  int rounds[3];
  rounds[0] = 3;
  rounds[1] = 5;
  rounds[2] = 8;
  for(int r=0; r<3; r++) {
    struct timeval stop, start;
    gettimeofday(&start, NULL);
    for(int i=0; i<1024; i++) {
      decipher(f_ring,offsets,0,check,0,sizeof(check),endian,rounds[r]);
    }
    gettimeofday(&stop, NULL);
    unsigned long elapsed_usec = (stop.tv_sec - start.tv_sec)*1000000L + (stop.tv_usec - start.tv_usec);
    unsigned long elapsed_sec = elapsed_usec / 1000000L;
    unsigned long mbytes_per_sec = 1000000L * 1024L / elapsed_sec / 1024L / 1024L;
    fprintf(stderr,"%lu Mbytes per second for %d rounds\n",mbytes_per_sec,rounds[r]);
  }

}

int main(int argc, char** argv) {
  check_cipher_accuracy();
  check_cipher_histogram();
  check_cipher_distribution();
  check_encipher_speed();
  check_decipher_speed();
  check_cipher_period();
}

