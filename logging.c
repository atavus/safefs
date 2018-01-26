#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include "logging.h"
#include "state.h"

int debug_on = 0;
int info_on = 0;

void logdebug(const char* fusecmd, const char* fmt, ...) {
  if (debug_on) {
    va_list va;
    va_start(va,fmt);
    time_t current_time = time(NULL);
    struct tm *tm = localtime(&current_time);
    char buf[30];
    asctime_r(tm,buf);
    fprintf(Y_STATE->logfile,"%s",buf);
    fprintf(Y_STATE->logfile,": %s : ",fusecmd);
    vfprintf(Y_STATE->logfile,fmt,va);
    fprintf(Y_STATE->logfile,"\n");
    fflush(Y_STATE->logfile);
  }
}

void loginfo(const char* fusecmd, const char* fmt, ...) {
  if (info_on) {
    va_list va;
    va_start(va,fmt);
    time_t current_time = time(NULL);
    struct tm *tm = localtime(&current_time);
    char buf[30];
    asctime_r(tm,buf);
    fprintf(Y_STATE->logfile,"%s",buf);
    fprintf(Y_STATE->logfile,": %s : ",fusecmd);
    vfprintf(Y_STATE->logfile,fmt,va);
    fprintf(Y_STATE->logfile,"\n");
    fflush(Y_STATE->logfile);
  }
}

void logdata(const char* fusecmd, const char* type, uint64_t ofs, const unsigned char* data, size_t size) {
  if (debug_on && data!=NULL) {
    time_t current_time = time(NULL);
    struct tm *tm = localtime(&current_time);
    char buf[30];
    asctime_r(tm,buf);
    fprintf(Y_STATE->logfile,"%s",buf);
    fprintf(Y_STATE->logfile,": %s : %s : size=%zu",fusecmd,type,size);
    for(uint64_t ptr=0; ptr<size; ptr++) {
      if ((ptr%16)==0) fprintf(Y_STATE->logfile,"\n%08llx",(ofs+ptr));
      fprintf(Y_STATE->logfile," %02x",data[ptr]);
    }
    fprintf(Y_STATE->logfile,"\n");
    fflush(Y_STATE->logfile);
  }
}

int logerr(const char* fusecmd, const char* fmt, ...) {
  int rc = -errno;
  va_list va;
  va_start(va,fmt);
  time_t current_time = time(NULL);
  struct tm *tm = localtime(&current_time);
  char buf[30];
  asctime_r(tm,buf);
  fprintf(Y_STATE->logfile,"%s",buf);
  fprintf(Y_STATE->logfile,": %s : Error [%d] %s\n\t",fusecmd,rc,strerror(errno));
  vfprintf(Y_STATE->logfile,fmt,va);
  fprintf(Y_STATE->logfile,"\n");
  fflush(Y_STATE->logfile);
  return rc;
}

