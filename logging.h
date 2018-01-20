#include <unistd.h>

void logdebug(const char* fusecmd, const char* fmt, ...);
void loginfo(const char* fusecmd, const char* fmt, ...);
void logdata(const char* fusecmd, const unsigned char* data, size_t size);
int logerr(const char* fusecmd, const char* fmt, ...);
