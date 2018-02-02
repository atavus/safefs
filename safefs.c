/*
 * FUSE file system to store files on cloud storage in encrypted form.
 * Very fast encryption/decryption and in-place encryption/decryption of any byte for fast updates.
 * By David Johnston
 * Copyright (c) 2015 David Johnston. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Install FUSE for MacOS here: https://osxfuse.github.io
 *
 * Inputs:
 * - 10 digit secret used to derive which 8 ring offsets to use (256 offsets available)
 * = 6.6e19 input combinations possible
 * = 1.8e19 ring offset combinations possible
 *
 * Each file has the following format:
 * - 256 byte random rotor settings (encrypted)
 * - file data encrypted using random rotor settings and ring offsets
 * = each files encrypted data is different even if the unencrypted data is the same
 * = each file is just 256 bytes larger than the original file size
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <pwd.h>
#include <stdarg.h>
#include <pthread.h>

#include "cipher.h"
#include "logging.h"
#include "state.h"
#include "md5.h"

int write_rotor(const char* cmd, const char* path, btnode* node, struct fuse_file_info* info) {
  int rc = 0;
  generate_random_rotor(node->f_ring,node->r_ring);
  unsigned char out[256];
  memcpy(out,node->f_ring,256);
  logdata(cmd,"rotor plain text",16,0,out,256);
  encode_rotor(out,Y_STATE->rotor_digest);
  logdata(cmd,"rotor cipher text",16,0,out,256);
  rc = pwrite(info->fh,out,256,0);
  memset(out,0,256);
  if (rc<0) {
    rc = logerr(cmd,"pwrite failed for write offsets: %s",path);
    return rc;
  } else if (rc!=256) {
    logerr(cmd,"pwrite failed for write offsets: %s",path);
    rc = -EIO;
    return rc;
  } else {
    rc = 0;
  }
  return rc;
}

int is_ds_store(const char* path) {
  return (path!=NULL & strlen(path)>=10 && !strcmp("/.DS_Store",&path[strlen(path)-10]));
}

void resolve(const char* path, char fpath[PATH_MAX]) {
  strcpy(fpath,Y_STATE->rootdir);
  strncat(fpath,path,PATH_MAX-strlen(Y_STATE->rootdir));
  if (is_ds_store(path)) {
    strcat(fpath,".");
  }
}

void determine_rotor_offsets(struct y_state *y_state, char *pwd) {

  // calculate the rotor offsets from the pin code
  memset(y_state->offsets,0,8);
  for(int i=0; i<8; i++) {
    y_state->offsets[i] = 0;
    for(int j=0; j<3; j++) {
      y_state->offsets[i] <<= 1;
      y_state->offsets[i] += (i+j);
      y_state->offsets[i] += pwd[i+j];
    }
  }

  // calculate the MD5 hash to use to check the correct pin was entered
  {
    MD5_CTX context;
    MD5Init (&context);
    MD5Update (&context, y_state->offsets, 8);
    MD5Update (&context, pwd, 8);
    MD5Update (&context, y_state->offsets, 8);
    MD5Final (y_state->safe_digest, &context);
  }

  // calculate the MD5 hash to use to encode the rotors
  {
    MD5_CTX context;
    MD5Init (&context);
    MD5Update (&context, y_state->offsets, 8);
    MD5Update (&context, y_state->safe_digest, 16);
    MD5Update (&context, y_state->offsets, 8);
    MD5Final (y_state->rotor_digest, &context);
  }

}

void check_rotor_offsets_match(struct y_state *y_state) {

  // determine the path of .safefs in the store
  char fpath[PATH_MAX];
  strcpy(fpath,y_state->rootdir);
  strcat(fpath,"/.safefs");

  // check the .safefs file or create it if missing
  int fd = open(fpath,O_RDONLY,0600);
  if (fd<0) {
    // cant open so try to create it
    fd = open(fpath,O_CREAT | O_TRUNC | O_WRONLY | O_EXCL,0600);
    if (fd<0) {
      perror("Failed to create .safefs");
      exit(1);
    } else {
      // write the rotor settings for the file
      unsigned char f_ring[256];
      unsigned char r_ring[256];
      generate_random_rotor(f_ring,r_ring);
      unsigned char out[256];
      memcpy(out,f_ring,256);
      encode_rotor(out,y_state->rotor_digest);
      int rc = pwrite(fd,out,256,0);
      if (rc!=256) {
        perror("Failed to write .safefs");
        close(fd);
        exit(1);
      }
      // write the enciphered digest to the file
      memcpy(out,y_state->safe_digest,16);
      encipher(f_ring,y_state->offsets,0,out,0,16,y_state->endian);
      rc = pwrite(fd,out,16,256);
      if (rc!=16) {
        perror("Failed to write .safefs");
        close(fd);
        exit(1);
      }
      close(fd);
    }
  } else {
    // read the rotor settings for the file
    unsigned char f_ring[256];
    unsigned char r_ring[256];
    int rc = pread(fd,f_ring,256,0);
    if (rc!=256) {
      perror("Failed to read .safefs");
      close(fd);
      exit(1);
    }
    decode_rotor(f_ring,y_state->rotor_digest);
    derive_reverse_rotor(f_ring,r_ring);
    // read and decipher the md5 hash stored in the file
    unsigned char out[16];
    rc = pread(fd,out,16,256);
    if (rc!=16) {
      perror("Failed to read .safefs");
      close(fd);
      exit(1);
    }
    decipher(r_ring,y_state->offsets,0,out,0,16,y_state->endian);
    close(fd);
    // check that the md5 hash matches
    if (memcmp(y_state->safe_digest,out,16)) {
      fprintf(stderr,"Incorrect pin code provided\n");
      exit(1);
    }
  }

}

// ----------------------------------------------------------------------
// Start OSXFUSE Implementation Here
// ----------------------------------------------------------------------

int y_getattr(const char *path, struct stat *stat) { 
  logdebug("y_getattr","path=%s",path);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = lstat(fpath,stat);
  if (rc<0) { if (errno!=ENOENT) rc = logerr("y_getattr","stat path=%s",path); else rc = -errno; }
  else { 
    if (stat->st_size>=256) stat->st_size -= 256; /* hide the first 256 bytes */ 
    logdebug("y_getattr","st_size=%lu",stat->st_size);
  }
  loginfo("y_getattr","path=%s rc=%d",path,rc);
  return rc; 
}

int y_readlink(const char *path, char *link, size_t size) { 
  logdebug("y_readlink","path=%s size=%d",path,size);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = readlink(fpath,link,size-1);
  if (rc<0) rc = logerr("y_readlink","readlink path=%s",path);
  else { 
    link[rc] = 0; rc = 0; 
    logdebug("y_readlink","link=%s",link);
  }
  loginfo("y_readlink","path=%s size=%d rc=%d",path,size,rc);
  return rc; 
}

//int y_getdir(const char *path, fuse_dirh_t dirh, fuse_dirfil_t dirfil) { }

int y_mknod(const char *path, mode_t mode, dev_t dev) { 
  logdebug("y_mknod","path=%s mode=%d",path,mode);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = mknod(fpath,mode,dev);
  if (rc<0) rc = logerr("y_mknod","mknod path=%s",path);
  loginfo("y_mknod","path=%s mode=%d rc=%d",path,mode,rc);
  return rc; 
}

int y_mkdir(const char *path, mode_t mode) { 
  logdebug("y_mkdir","path=%s mode=%d",path,mode);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = mkdir(fpath,mode);
  if (rc<0) rc = logerr("y_mkdir","mkdir path=%s",path);
  loginfo("y_mkdir","path=%s mode=%d rc=%d",path,mode,rc);
  return rc; 
}

int y_unlink(const char *path) {
  logdebug("y_unlink","path=%s",path);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = unlink(fpath);
  if (rc<0) rc = logerr("y_unlink","unlink path=%s",path);
  loginfo("y_unlink","path=%s rc=%d",path,rc);
  return rc; 
}

int y_rmdir(const char *path) {
  logdebug("y_rmdir","path=%s",path);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = rmdir(fpath);
  if (rc<0) rc = logerr("y_rmdir","rmdir path=%s",path);
  loginfo("y_rmdir","path=%s rc=%d",path,rc);
  return rc; 
}

int y_symlink(const char *target, const char *path) {
  logdebug("y_symlink","target=%s path=%s",target,path);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = symlink(target,fpath);
  if (rc<0) rc = logerr("y_symlink","symlink target=%s path=%s",target,path);
  loginfo("y_symlink","target=%s path=%s rc=%d",target,path,rc);
  return rc; 
}

int y_rename(const char *path, const char *path2) {
  logdebug("y_rename","path=%s path2=%s",path,path2);
  int rc = 0;
  char fpath[PATH_MAX];
  char fpath2[PATH_MAX];
  resolve(path,fpath);
  resolve(path2,fpath2);
  rc = rename(fpath,fpath2);
  if (rc<0) rc = logerr("y_rename","rename path=%s path2=%s",path,path2);
  loginfo("y_rename","path=%s path2=%s rc=%d",path,path2,rc);
  return rc; 
}

int y_link(const char *path, const char *path2) {
  logdebug("y_link","path=%s path2=%s",path,path2);
  int rc = 0;
  char fpath[PATH_MAX];
  char fpath2[PATH_MAX];
  resolve(path,fpath);
  resolve(path2,fpath2);
  rc = link(fpath,fpath2);
  if (rc<0) rc = logerr("y_link","link path=%s path2=%s",path,path2);
  loginfo("y_link","path=%s path2=%s rc=%d",path,path2,rc);
  return rc; 
}

int y_chmod(const char *path, mode_t mode) {
  logdebug("y_chmod","path=%s mode=%x",path,mode);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = chmod(fpath,mode);
  if (rc<0) rc = logerr("y_chmod","chmod path=%s mode=%d",path,mode);
  loginfo("y_chmod","path=%s mode=%x rc=%d",path,mode,rc);
  return rc; 
}

int y_chown(const char *path, uid_t uid, gid_t gid) {
  logdebug("y_chown","path=%s uid=%d gid=%d",path,uid,gid);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = chown(fpath,uid,gid);
  if (rc<0) rc = logerr("y_chown","chown path=%s uid=%d gid=%d",path,uid,gid);
  loginfo("y_chown","path=%s uid=%d gid=%d rc=%d",path,uid,gid,rc);
  return rc; 
}

int y_truncate(const char *path, off_t off) {
  logdebug("y_truncate","path=%s offset=%d",path,off);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  // truncate the file skipping the first 256 bytes
  rc = truncate(fpath,off+256);
  if (rc<0) rc = logerr("y_truncate","truncate path=%s offset=%d",path,off);
  loginfo("y_truncate","path=%s offset=%d rc=%d",path,off,rc);
  return rc; 
}

int y_utime(const char *path, struct utimbuf *time) {
  logdebug("y_utime","path=%s actime=%lu modtime=%lu",path,time->actime,time->modtime);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = utime(fpath,time);
  if (rc<0) rc = logerr("y_utime","utime path=%s",path);
  loginfo("y_utime","path=%s actime=%lu modtime=%lu rc=%d",path,time->actime,time->modtime,rc);
  return rc; 
}

int y_open(const char *path, struct fuse_file_info *info) {
  logdebug("y_open","path=%s flags=%d",path,info->flags);
  int rc = 0;
  int fd;
  char fpath[PATH_MAX];
  unsigned char f_ring[256];
  unsigned char r_ring[256];
  int loaded = 0;
  int truncate = 0;
  resolve(path,fpath);
  // try to read the existing rotor settings for the file
  int flags = info->flags;
  fd = open(fpath,O_RDONLY); 
  if (fd>=0) {
    rc = pread(fd,f_ring,256,0);
    if (rc!=256) {
      rc = logerr("y_open","pread path=%s",path);
    } else {
      logdata("y_open","rotor cipher text",16,0,f_ring,256);
      decode_rotor(f_ring,Y_STATE->rotor_digest);
      logdata("y_open","rotor plain text",16,0,f_ring,256);
      derive_reverse_rotor(f_ring,r_ring);
      loaded = 1;
      rc = 0;
    }
    close(fd);
  } else {
    rc = logerr("y_open","open path=%s",path);
  }
  // dont use the standard O_TRUNC function because it truncates to zero bytes
  if ((flags&O_TRUNC)==O_TRUNC) {
    flags ^= O_TRUNC;
    truncate = 1;
  }
  // if the rotor settings were read then open the file with the requested flags
  if (rc==0) {
    fd = open(fpath,flags);
    if (fd<0) {
      rc = logerr("y_open","open path=%s",path);
    } else { 
      logdebug("y_open","fd=%d path=%s",fd,path);
      info->fh = fd; 
      btnode* node = addLink(fd,&Y_STATE->list); 
      if (!loaded) {
        if ((flags&O_CREAT)==O_CREAT) {
          rc = write_rotor("y_open",path,node,info);
        } else {
          logerr("y_open","failed to load rotor settings path=%s",path);
          rc = -EIO;
        }
      } else {
        memcpy(node->f_ring,f_ring,256);
        memcpy(node->r_ring,r_ring,256);
      }
      if (rc==0) {
        if (truncate) {
          rc = ftruncate(info->fh, 256);
          if (rc<0) rc = logerr("y_open","ftruncate path=%s pos=%d",path,0);
        }
      }
    }
  }
  memset(f_ring,0,256);
  memset(r_ring,0,256);
  loginfo("y_open","path=%s flags=%d rc=%d",path,info->flags,rc);
  return rc; 
}

int y_read(const char *path, char *data, size_t size, off_t ofs, struct fuse_file_info *info) {
  logdebug("y_read","path=%s size=%d ofs=%d",path,size,ofs);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  // get the node entry for this file descriptor
  btnode *node = findLink(info->fh,&Y_STATE->list);
  if (node==NULL) {
    logerr("y_read","find path=%s failed to find node",path);
    rc = -EIO;
    return rc;
  }
  // read from the file skipping the first 256 bytes
  rc = pread(info->fh,data,size,ofs+256);
  if (rc<0) { 
    rc = logerr("y_read","pread path=%s",path);
  } else { 
    if (trace_on) {
      logdata("y_read","forward rotors",16,0,node->f_ring,256);
      logdata("y_read","reverse rotors",16,0,node->r_ring,256);
      logdata("y_read","rotor offsets",16,0,Y_STATE->offsets,8);
      logdata("y_read","cipher text",64,ofs,(unsigned char*)data,rc);
    }
    decipher(node->r_ring,Y_STATE->offsets,ofs,(unsigned char*)data,0,rc,Y_STATE->endian);
    if (trace_on) {
      logdata("y_read","plain text",64,ofs,(unsigned char*)data,rc);
    }
  }
  loginfo("y_read","path=%s size=%d ofs=%d rc=%d",path,size,ofs,rc);
  return rc; 
}

int y_write(const char *path, const char *data, size_t size, off_t ofs, struct fuse_file_info *info) { 
  logdebug("y_write","path=%s offset=%d size=%d",path,ofs,size);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  // get the node entry for this file descriptor
  btnode *node = findLink(info->fh,&Y_STATE->list);
  if (node==NULL) {
    logerr("y_write","find path=%s failed to find node",path);
    rc = -EIO;
    loginfo("y_write","rc=%d",rc);
    return rc;
  }
  // encipher the plain text and then write to the file skipping the first 256 bytes
  unsigned char *buf = malloc(size);
  memcpy(buf,data,size);
  if (trace_on) {
    logdata("y_write","forward rotors",16,0,node->f_ring,256);
    logdata("y_write","reverse rotors",16,0,node->r_ring,256);
    logdata("y_write","rotor offsets",16,0,Y_STATE->offsets,8);
    logdata("y_write","plain text",64,ofs,buf,size);
  }
  encipher(node->f_ring,Y_STATE->offsets,ofs,buf,0,size,Y_STATE->endian);
  if (trace_on) {
    logdata("y_write","cipher text",64,ofs,buf,size);
  }
  rc = pwrite(info->fh,buf,size,ofs+256);
  if (rc<0) {
    rc = logerr("y_write","pwrite path=%s",path);
  }
  free(buf);
  loginfo("y_write","path=%s offset=%d size=%d rc=%d",path,ofs,size,rc);
  return rc; 
}

int y_statfs(const char *path, struct statvfs *stat) { 
  logdebug("y_statfs","path=%s",path);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = statvfs(fpath,stat);
  if (rc<0) rc = logerr("y_statfs","statvfs path=%s",path);
  loginfo("y_statfs","path=%s rc=%d",path,rc);
  return rc; 
}

//int y_flush(const char *path, struct fuse_file_info *info) { }

int y_release(const char *path, struct fuse_file_info *info) { 
  logdebug("y_release","path=%s",path);
  int rc = 0;
  rc = close(info->fh);
  if (rc<0) rc = logerr("y_release","close path=%s",path);
  logdebug("y_release","%d %s",info->fh,path);
  delLink(info->fh,&Y_STATE->list);
  info->fh = 0;
  loginfo("y_release","path=%s rc=%d",path,rc);
  return rc; 
}

int y_fsync(const char *path, int datasync, struct fuse_file_info *info) { 
  logdebug("y_fsync","path=%s datasync=%d",path,datasync);
  int rc = 0;
  rc = fsync(info->fh);
  if (rc<0) rc = logerr("y_fsync","fsync path=%s",path);
  loginfo("y_fsync","path=%s datasync=%d rc=%d",path,datasync,rc);
  return rc; 
}

int y_setxattr(const char *path, const char *name, const char *val, size_t size, int pos, uint32_t opts) {
  logdebug("y_setxattr","path=%s name=%s size=%d pos=%d opts=%d",path,name,size,pos,opts);
  logdata("y_setxattr","value",64,0,(unsigned char*)val,size);
  if (!strcmp("com.apple.quarantine",name)) return 0;
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  if (strcmp("com.apple.ResourceFork",name)) pos=0; // only ResourceFork uses this field, all others must be zero
  rc = setxattr(fpath,name,val,size,pos,opts);
  if (rc<0) rc = logerr("y_setxattr","setxattr path=%s name=%s",path,name);
  loginfo("y_setxattr","path=%s name=%s size=%d pos=%d opts=%d rc=%d",path,name,size,pos,opts,rc);
  return rc; 
}

int y_getxattr(const char *path, const char *name, char *val, size_t size, uint32_t opts) { 
  logdebug("y_getxattr","path=%s name=%s size=%d opts=%d",path,name,size,opts);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = getxattr(fpath,name,val,size,0,opts);
  if (rc<0) { if (errno!=ENOATTR) rc = logerr("y_getxattr","getxattr path=%s name=%s",path,name); else rc = -errno; }
  else { logdata("y_getxattr","value",64,0,(unsigned char*)val,rc); }
  loginfo("y_getxattr","path=%s name=%s size=%d opts=%d rc=%d",path,name,size,opts,rc);
  return rc; 
}

int y_listxattr(const char *path, char *name, size_t size) { 
  logdebug("y_listxattr","path=%s size=%d",path,size);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = listxattr(fpath,name,size,0);
  if (rc<0) rc = logerr("y_listxattr","listxattr path=%s name=%s",path,name);
  loginfo("y_listxattr","path=%s size=%d rc=%d",path,size,rc);
  return rc; 
}

int y_removexattr(const char *path, const char *name) { 
  logdebug("y_removexattr","path=%s name=%s",path,name);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = removexattr(fpath,name,0);
  if (rc<0) rc = logerr("y_removexattr","removexattr path=%s name=%s",path,name);
  loginfo("y_removexattr","path=%s name=%s rc=%d",path,name,rc);
  return rc; 
}

int y_opendir(const char *path, struct fuse_file_info *info) { 
  logdebug("y_opendir","path=%s",path);
  int rc = 0;
  DIR *dp;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  dp = opendir(fpath);
  info->fh = (intptr_t)dp;
  if (dp==NULL) rc = logerr("y_opendir","opendir path=%s",path);
  loginfo("y_opendir","path=%s rc=%d",path,rc);
  return rc; 
}

int y_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info) { 
  logdebug("y_readdir","path=%s",path);
  int rc = 0;
  DIR *dp;
  struct dirent *dent = NULL;
  //dp = (DIR*)(uintptr_t)info->fh;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  dp = opendir(fpath);
  if (dp==NULL) {
    rc = logerr("y_readdir","opendir path=%s",path);
  } else {
    dent = readdir(dp);
    if (dent == NULL) {
      rc = logerr("y_readdir","readdir path=%s",path);
    } else {
      do {
        struct stat st;
        st.st_ino = dent->d_ino;
        st.st_mode = dent->d_type << 12;
        if (!strcmp(dent->d_name,".DS_Store.")) {
          if (filler(buf, ".DS_Store", &st, 0) != 0) {
            logerr("y_readdir","filler path=%s",path);
            rc = -ENOMEM;
            break;
          }
        } else {
          if (filler(buf, dent->d_name, &st, 0) != 0) {
            logerr("y_readdir","filler path=%s",path);
            rc = -ENOMEM;
            break;
          }
        }
      } while (( dent = readdir(dp)) != NULL);
    }
    closedir(dp);
  }
  loginfo("y_readdir","path=%s rc=%d",path,rc);
  return rc;
}

int y_releasedir(const char *path, struct fuse_file_info *info) { 
  logdebug("y_releasedir","path=%s",path);
  int rc = 0;
  DIR *dp;
  dp = (DIR*)(uintptr_t)info->fh;
  rc = closedir(dp);
  if (rc<0) rc = logerr("y_releasedir","releasedir path=%s",path);
  else info->fh = 0;
  loginfo("y_releasedir","path=%s rc=%d",path,rc);
  return rc; 
}

//int y_fsyncdir(const char *path, int arg1, struct fuse_file_info *info) { }

void *y_init(struct fuse_conn_info *conn) { 
  return Y_STATE; 
}

void y_destroy(void *conn) { }

int y_access(const char *path, int mask) { 
  logdebug("y_access","path=%s mask=%d",path,mask);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = access(fpath,mask);
  if (rc<0) { if (errno!=EACCES) rc = logerr("y_access","access path=%s mask=%d",path,mask); else rc = -errno; }
  logdebug("y_access","path=%s mask=%d rc=%d",path,mask,rc);
  return rc; 
}

int y_create(const char *path, mode_t mode, struct fuse_file_info *info) { 
  logdebug("y_create","path=%s mode=%d",path,mode);
  int rc = 0;
  int fd;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  fd = open(fpath, O_CREAT | O_TRUNC | O_WRONLY, mode);
  if (fd<0) {
    rc = logerr("y_create","creat path=%s mode=%d",path,mode);
  } else { 
    logdebug("y_create","fd=%d path=%s",fd,path);
    info->fh = fd; 
    btnode* node = addLink(fd,&Y_STATE->list); 
    rc = write_rotor("y_create",path,node,info);
  }
  loginfo("y_create","path=%s mode=%d rc=%d",path,mode,rc);
  return rc; 
}

int y_ftruncate(const char *path, off_t pos, struct fuse_file_info *info) { 
  logdebug("y_ftruncate","path=%s pos=%d",path,pos);
  int rc = 0;
  // truncate the file skipping the first 256 bytes
  rc = ftruncate(info->fh, pos+256);
  if (rc<0) rc = logerr("y_ftruncate","ftruncate path=%s pos=%d",path,pos);
  loginfo("y_ftruncate","path=%s pos=%d rc=%d",path,pos,rc);
  return rc; 
}

int y_fgetattr(const char *path, struct stat *stat, struct fuse_file_info *info) { 
  logdebug("y_fgetattr","path=%s",path);
  int rc = 0;
  rc = fstat(info->fh,stat);
  if (rc<0) rc = logerr("y_fgetattr","fstat path=%s",path);
  else { if (stat->st_size>=256) stat->st_size -= 256; /* hide the first 256 bytes */ }
  loginfo("y_fgetattr","path=%s size=%lu rc=%d",path,stat->st_size,rc);
  return rc; 
}

int y_lock(const char *path, struct fuse_file_info *info, int cmd, struct flock *flock) { 
  logdebug("y_lock","path=%s cmd=%d",path,cmd);
  int rc = 0;
  rc = fcntl(info->fh,cmd,flock);
  if (rc<0) rc = logerr("y_lock","fcntl path=%s",path);
  loginfo("y_lock","path=%s cmd=%d rc=%d",path,cmd,rc);
  return rc; 
}

//int y_utimens(const char *path, const struct timespec tv[2]) { }

//int y_bmap(const char *path, size_t blocksize, uint64_t *idx) { }

//int y_setvolname(const char *path) { }

//int y_exchange(const char *oldpath, const char *newpath, unsigned long flags) { }

//int y_getxtimes(const char *path, struct timespec *bkuptime, struct timespec *crtime) { }
//int y_setbkuptime(const char *path, const struct timespec *tv) { }
//int y_setchgtime(const char *path, const struct timespec *tv) { }
//int y_setcrtime(const char *path, const struct timespec *tv) { }

int y_chflags(const char *path, uint32_t flags) { 
  logdebug("y_chflags","path=%s flags=%d",path,flags);
  int rc = 0;
  char fpath[PATH_MAX];
  resolve(path,fpath);
  rc = chflags(fpath,flags);
  if (rc<0) rc = logerr("y_chflags","chflags path=%s flags=%d",path,flags);
  loginfo("y_chflags","path=%s flags=%d rc=%d",path,flags,rc);
  return rc;
}

//int y_setattr_x(const char *path, struct setattr_x *arg1) { }
//int y_fsetattr_x(const char *path, struct setattr_x *arg1, struct fuse_file_info *info) { }

struct fuse_operations y_ops = {

  .getattr = y_getattr,
  .readlink = y_readlink,
  .mknod = y_mknod,
  .mkdir = y_mkdir,
  .unlink = y_unlink,
  .rmdir = y_rmdir,
  .symlink = y_symlink,
  .rename = y_rename,
  .link = y_link,
  .chmod = y_chmod,
  .chown = y_chown,
  .truncate = y_truncate,
  .utime = y_utime,
  .open = y_open,
  .read = y_read,
  .write = y_write,
  .statfs = y_statfs,
  .release = y_release,
  .fsync = y_fsync,
  .setxattr = y_setxattr,
  .getxattr = y_getxattr,
  .listxattr = y_listxattr,
  .removexattr = y_removexattr,
  .opendir = y_opendir,
  .readdir = y_readdir,
  .releasedir = y_releasedir,
  .init = y_init,
  .destroy = y_destroy,
  .access = y_access,
  .create = y_create,
  .ftruncate = y_ftruncate,
  .fgetattr = y_fgetattr,
  .lock = y_lock,
  .chflags = y_chflags

};

int main(int argc, char** argv) {

  struct y_state *y_state;

  if (getuid()==0 || geteuid()==0) {
    fprintf(stderr,"Cannot run as root\n");
    exit(1);
  }

  // interpret the command line options
  char  options[1024];
  char  storage[1024];
  char  mount[1024];
  char  logfile[1024];
  memset(options,0,sizeof(options));
  memset(storage,0,sizeof(storage));
  memset(mount,0,sizeof(mount));
  memset(logfile,0,sizeof(logfile));
  for(int i=1; i<argc; i++) {
    if (!strcmp("-trace",argv[i])) { trace_on = 1; debug_on = 1; info_on = 1; }
    else if (!strcmp("-debug",argv[i])) { debug_on = 1; info_on = 1; }
    else if (!strcmp("-info",argv[i])) { info_on = 1; }
    else if (!strcmp("-dump-ascii",argv[i])) { data_ascii = 1; }
    else if (strlen(argv[i])>2 && !(memcmp("-o",argv[i],2))) strcpy(options,argv[i]);
    else if (strlen(argv[i])>2 && !(memcmp("-s",argv[i],2))) strcpy(storage,&argv[i][2]);
    else if (strlen(argv[i])>2 && !(memcmp("-m",argv[i],2))) strcpy(mount,&argv[i][2]);
    else if (strlen(argv[i])>2 && !(memcmp("-l",argv[i],2))) strcpy(logfile,&argv[i][2]);
  }
  if (strlen(storage)==0 || strlen(mount)==0) {
    fprintf(stderr,"Syntax: safefs [-trace|-debug|-info] [-dump-ascii] [-o<options>] [-l<log-file-path>] -s<file-system-storage-path> -m<mount-point>\n");
    exit(1);
  }
  if (strlen(options)==0) {
    strcpy(options,"-ovolname=safe");
  } else if (strstr(options,"volname=")==NULL) {
    strcat(options,",volname=safe");
  }
  if (strstr(options,"direct_io")==NULL) {
    strcat(options,",direct_io");
  }
  if (strstr(options,"hard_remove")==NULL) {
    strcat(options,",hard_remove");
  }
  if (strstr(options,"use_ino")==NULL) {
    strcat(options,",use_ino");
  }
  if (strstr(options,"exec")==NULL) {
    strcat(options,",exec");
  }
  if (strlen(logfile)==0) {
    strcpy(logfile,"safefs.log");
  }
  if (storage[strlen(storage)-1]!='/') {
    strcat(storage,"/");
  }
  if (mount[strlen(mount)-1]!='/') {
    strcat(mount,"/");
  }

  // seed the random number generator
  srandomdev();

  // create fuse state
  y_state = calloc(1,sizeof(struct y_state));
  if (y_state==NULL) {
    fprintf(stderr,"Out of memory\n");
    exit(1);
  }

  // create the fuse log file
  y_state->logfile = fopen(logfile,"w");
  if (y_state->logfile==NULL) {
    fprintf(stderr,"Cannot open log file [%s] for writing\n",logfile);
    exit(1);
  }

  // set the storage location as the root directory
  strcpy(y_state->rootdir,realpath(storage,NULL));

  // determine which rotor offsets to use
  {
    char *pwd = getenv("SAFEFS_PIN");
    if (pwd==NULL) {
      pwd = getpass("Enter the 10-digit pin code:");
    }
    if (strlen(pwd)!=10) {
      memset(pwd,0,strlen(pwd));
      fprintf(stderr,"Invalid pin code length\n");
	  exit(1);
    }
    determine_rotor_offsets(y_state,pwd);
    memset(pwd,0,strlen(pwd));
  }

  // determine if little endian or big endian
  y_state->endian = determine_endianness(y_state->offsets);

  // check the md5 hash matches
  check_rotor_offsets_match(y_state);

  // validate that the cipher algorithm is working properly
  {
    unsigned char f_ring[256];
    unsigned char r_ring[256];
    generate_random_rotor(f_ring,r_ring);
    unsigned char orig[65536];
	unsigned char check[65536];
	for(int i=0; i<65536; i++) {
	  check[i] = i;
	}
	memcpy(orig,check,65536);
    encipher(f_ring,y_state->offsets,0,check,0,65536,y_state->endian);
	if (!memcmp(orig,check,65536)) {
      fprintf(stderr,"encipher algorithm broken\n");
	  exit(1);
	}
    decipher(r_ring,y_state->offsets,0,check,0,65536,y_state->endian);
	if (memcmp(orig,check,65536)) {
      fprintf(stderr,"decipher algorithm broken\n");
	  exit(1);
	}
  }

  // execute fuse
  fprintf(stderr,"Mounting filesystem [%s] using storage [%s] and options [%s]\n",mount,storage,options);
  char *args[3];
  args[0] = argv[0];
  args[1] = options;
  args[2] = mount;
  return fuse_main(3, args, &y_ops, y_state);

}

