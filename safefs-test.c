#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int check_file_create(const char* store, const char* access) {
  fprintf(stderr,"Check that file creation works\n");
  char fpath[PATH_MAX];
  strcpy(fpath,access);
  strcat(fpath,"x");
  unlink(fpath);
  int mode=0600;
  int fd = open(fpath, O_CREAT | O_TRUNC | O_WRONLY, mode);
  if (fd<0) {
    perror("Failed to open file");
    return 1;
  } else {
    close(fd);
  }
  return 0;
}

int check_file_write(const char* store, const char* access) {
  fprintf(stderr,"Check that file writing works\n");
  char fpath[PATH_MAX];
  strcpy(fpath,access);
  strcat(fpath,"x");
  int mode=0600;
  int fd = open(fpath, O_WRONLY, mode);
  if (fd<0) {
    perror("Failed to open file");
    return 1;
  } else {
    int rc = pwrite(fd,"hello",5,0);
    if (rc<0) {
      perror("Failed to write to file");
      close(fd);
      return 1;
    }
    struct stat stat;
    rc = fstat(fd,&stat);
    if (rc<0) {
      perror("Failed to check file size");
      close(fd);
      return 1;
    }
    if (stat.st_size!=5) {
      fprintf(stderr,"File size is incorrect after writing. %lld\n",stat.st_size);
      close(fd);
      return 1;
    }
    close(fd);
  }
  return 0;
}

int check_file_read(const char* store, const char* access) {
  fprintf(stderr,"Check that file reading works\n");
  char fpath[PATH_MAX];
  strcpy(fpath,access);
  strcat(fpath,"x");
  int mode=0600;
  int fd = open(fpath, O_RDONLY, mode);
  if (fd<0) {
    perror("Failed to open file");
    return 1;
  } else {
    unsigned char data[5];
    int rc = pread(fd,data,5,0);
    if (rc<0) {
      perror("Failed to read from file");
      close(fd);
      return 1;
    } else if (rc!=5) {
      fprintf(stderr,"Failed to read all bytes from file\n");
      close(fd);
      return 1;
    } else {
      if (memcmp("hello",data,5)) {
        fprintf(stderr,"Incorrect data read from file\n");
        close(fd);
        return 1;
      }
    }
    close(fd);
  }
  return 0;
}

int check_file_truncate(const char* store, const char* access) {
  fprintf(stderr,"Check that file truncation works\n");
  char fpath[PATH_MAX];
  strcpy(fpath,access);
  strcat(fpath,"x");
  int mode=0600;
  int fd = open(fpath, O_WRONLY | O_TRUNC, mode);
  if (fd<0) {
    perror("Failed to open file");
    return 1;
  } else {
    struct stat stat;
    int rc = fstat(fd,&stat);
    if (rc<0) {
      perror("Failed to check file size");
      close(fd);
      return 1;
    }
    if (stat.st_size!=0) {
      fprintf(stderr,"File size is incorrect after truncating. %lld\n",stat.st_size);
      close(fd);
      return 1;
    }
    close(fd);
  }
  return 0;
}

int check_file_unlink(const char* store, const char* access) {
  fprintf(stderr,"Check that file unlink works\n");
  char fpath[PATH_MAX];
  strcpy(fpath,access);
  strcat(fpath,"x");
  int rc = unlink(fpath);
  if (rc<0) {
    perror("Failed to unlink file");
    return 1;
  }
  return 0;
}

int check_random_write_test(const char* store, const char* access) {
  fprintf(stderr,"Check random writes work\n");
  char fpath[PATH_MAX];
  unsigned char out[512];
  unsigned char in[512];

  strcpy(fpath,access);
  strcat(fpath,"x");
  unlink(fpath);

  for(uint64_t ofs=0; ofs<1000000; ofs+=128) {
    for(int i=0; i<512; i++) {
      out[i] = random();
    }
    int mode=0600;
    int fd = open(fpath, O_CREAT | O_WRONLY, mode);
    if (fd<0) {
      perror("Failed to open file for writing");
      return 1;
    } else {
      int rc = pwrite(fd,out,512,ofs);
      if (rc<0) {
        perror("Failed to write to file");
        close(fd);
        return 1;
      }
      close(fd);
    }
    fd = open(fpath, O_RDONLY, mode);
    if (fd<0) {
      perror("Failed to open file for reading");
      return 1;
    } else {
      int rc = pread(fd,in,512,ofs);
      if (rc<0) {
        perror("Failed to read from file");
        close(fd);
        return 1;
      } else if (rc!=512) {
        perror("Short read from file");
        close(fd);
        return 1;
      } else {
        if (memcmp(out,in,512)) {
          perror("Failed to read the correct data from the file");
          close(fd);
          return 1;
        }
        close(fd);
      }
    }
  }
  return 0;
}

int check_rainbow_test(const char* store, const char* access) {
  fprintf(stderr,"Check that rainbow table protection works\n");
  char fpath[PATH_MAX];

  unsigned char data[512];
  memset(data,'a',512);

  // write x
  strcpy(fpath,access);
  strcat(fpath,"x");
  unlink(fpath);
  int mode=0600;
  int fd = open(fpath, O_CREAT | O_TRUNC | O_WRONLY, mode);
  if (fd<0) {
    perror("Failed to open file");
    return 1;
  } else {
    int rc = pwrite(fd,data,512,0);
    if (rc<0) {
      perror("Failed to write to file");
      close(fd);
      return 1;
    }
    close(fd);
  }

  // check that x was written correctly
  unsigned char input[512];
  fd = open(fpath, O_RDONLY, mode);
  if (fd<0) {
    perror("Failed to open file");
    return 1;
  } else {
    int rc = pread(fd,input,512,0);
    if (rc!=512) {
      perror("Failed to read file");
      close(fd);
      return 1;
    }
    close(fd);
  }
  if (memcmp(data,input,512)) {
    fprintf(stderr,"Read incorrect data\n");
    return 1;
  }

  // write y
  strcpy(fpath,access);
  strcat(fpath,"y");
  unlink(fpath);
  mode=0600;
  fd = open(fpath, O_CREAT | O_TRUNC | O_WRONLY, mode);
  if (fd<0) {
    perror("Failed to open file");
    return 1;
  } else {
    int rc = pwrite(fd,data,512,0);
    if (rc<0) {
      perror("Failed to write to file");
      close(fd);
      return 1;
    }
    close(fd);
  }

  // check that y was written correctly
  fd = open(fpath, O_RDONLY, mode);
  if (fd<0) {
    perror("Failed to open file");
    return 1;
  } else {
    int rc = pread(fd,input,512,0);
    if (rc!=512) {
      perror("Failed to read file");
      close(fd);
      return 1;
    }
    close(fd);
  }
  if (memcmp(data,input,512)) {
    fprintf(stderr,"Read incorrect data\n");
    return 1;
  }

  // read the encrypted content of x
  unsigned char x[1024];
  memset(x,0,1024);
  strcpy(fpath,store);
  strcat(fpath,"x");
  fd = open(fpath, O_RDONLY, mode);
  if (fd<0) {
    perror("Failed to open real file");
    return 1;
  } else {
    int rc = pread(fd,x,1024,0);
    if (rc!=772) {
      perror("Failed to read the correct number of bytes");
      close(fd);
      return 1;
    }
    close(fd);
  }

  // read the encrypted content of y
  unsigned char y[1024];
  memset(y,0,1024);
  strcpy(fpath,store);
  strcat(fpath,"y");
  fd = open(fpath, O_RDONLY, mode);
  if (fd<0) {
    perror("Failed to open real file");
    return 1;
  } else {
    int rc = pread(fd,x,1024,0);
    if (rc!=772) {
      perror("Failed to read the correct number of bytes");
      close(fd);
      return 1;
    }
    close(fd);
  }

  // check that the salt bytes are different
  if (!memcmp(x,y,4)) {
    fprintf(stderr,"File salt are identical\n");
    return 1;
  }

  // check that the rotor bytes are different
  if (!memcmp(&x[4],&y[4],256)) {
    fprintf(stderr,"File rotor settings are identical\n");
    return 1;
  }

  // check that the encrypted values are different
  if (!memcmp(&x[260],&y[260],512)) {
    fprintf(stderr,"File encryption values are identical\n");
    return 1;
  }

  return 0;
}

int main(int argc, char** argv) {
  char* store = argv[1];
  char* access = argv[2];
  int rc = 0;
  rc |= check_file_create(store,access);
  rc |= check_file_write(store,access);
  rc |= check_file_read(store,access);
  rc |= check_file_truncate(store,access);
  rc |= check_file_unlink(store,access);
  rc |= check_rainbow_test(store,access);
  rc |= check_random_write_test(store,access);
  return rc;
}

