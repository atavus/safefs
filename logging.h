#include <unistd.h>

extern int debug_on;
extern int info_on;
extern int data_ascii;

void logdebug(const char* fusecmd, const char* fmt, ...);
void loginfo(const char* fusecmd, const char* fmt, ...);
void logdata(const char* fusecmd, const char* type, uint64_t ofs, const unsigned char* data, size_t size);
int logerr(const char* fusecmd, const char* fmt, ...);
