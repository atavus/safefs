#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include "logging.h"
#include "state.h"

int trace_on = 0;
int debug_on = 0;
int info_on = 0;
int data_ascii = 0;

pthread_mutex_t mutexlog = PTHREAD_MUTEX_INITIALIZER;

void logdebug(const char* fusecmd, const char* fmt, ...) {
  if (debug_on) {
    pthread_mutex_lock(&mutexlog);
    va_list va;
    va_start(va,fmt);
    time_t current_time = time(NULL);
    struct tm *tm = localtime(&current_time);
    char buf[30];
    asctime_r(tm,buf);
    buf[strlen(buf)-1]=0;
    fprintf(Y_STATE->logfile,"%s : %-14s : ",buf,fusecmd);
    vfprintf(Y_STATE->logfile,fmt,va);
    fprintf(Y_STATE->logfile,"\n");
    fflush(Y_STATE->logfile);
    pthread_mutex_unlock(&mutexlog);
  }
}

void loginfo(const char* fusecmd, const char* fmt, ...) {
  if (info_on) {
    pthread_mutex_lock(&mutexlog);
    va_list va;
    va_start(va,fmt);
    time_t current_time = time(NULL);
    struct tm *tm = localtime(&current_time);
    char buf[30];
    asctime_r(tm,buf);
    buf[strlen(buf)-1]=0;
    fprintf(Y_STATE->logfile,"%s : %-14s : ",buf,fusecmd);
    vfprintf(Y_STATE->logfile,fmt,va);
    fprintf(Y_STATE->logfile,"\n");
    fflush(Y_STATE->logfile);
    pthread_mutex_unlock(&mutexlog);
  }
}

void logdata(const char* fusecmd, const char* type, uint64_t width, uint64_t ofs, const unsigned char* data, size_t size) {
  if (trace_on && data!=NULL) {
    pthread_mutex_lock(&mutexlog);
    time_t current_time = time(NULL);
    struct tm *tm = localtime(&current_time);
    char buf[30];
    asctime_r(tm,buf);
    buf[strlen(buf)-1]=0;
    fprintf(Y_STATE->logfile,"%s : %-14s : %s : offset=%llu size=%zu",buf,fusecmd,type,ofs,size);
    for(uint64_t ptr=0; ptr<size; ptr++) {
      if ((ptr%width)==0) fprintf(Y_STATE->logfile,"\n%08llx",(ofs+ptr));
      if (data_ascii && data[ptr]>31 && data[ptr]<127) {
        fprintf(Y_STATE->logfile,"  %c",data[ptr]);
      } else {
        fprintf(Y_STATE->logfile," %02x",data[ptr]);
      }
    }
    fprintf(Y_STATE->logfile,"\n");
    fflush(Y_STATE->logfile);
    pthread_mutex_unlock(&mutexlog);
  }
}

int logerr(const char* fusecmd, const char* fmt, ...) {
  pthread_mutex_lock(&mutexlog);
  int rc = -errno;
  va_list va;
  va_start(va,fmt);
  time_t current_time = time(NULL);
  struct tm *tm = localtime(&current_time);
  char buf[30];
  asctime_r(tm,buf);
  buf[strlen(buf)-1]=0;
  fprintf(Y_STATE->logfile,"%s : %-14s : Error [%d] %s\n\t",buf,fusecmd,rc,strerror(errno));
  vfprintf(Y_STATE->logfile,fmt,va);
  fprintf(Y_STATE->logfile,"\n");
  fflush(Y_STATE->logfile);
  pthread_mutex_unlock(&mutexlog);
  return rc;
}

