#ifndef _UTIL_H
#define _UTIL_H

void prefixprintf(char *prefix, int fd, const char *format, ...);

#define fatal(fd, ...) \
    do { \
        prefixprintf("fatal:", fd, __VA_ARGS__); \
        exit(-1); \
    } while(0)

#define error(fd, ...) \
    prefixprintf("error:", fd, __VA_ARGS__); \

#define warning(fd, ...) \
    prefixprintf("warning:", fd, __VA_ARGS__); \
    
#define info(fd, ...) \
    prefixprintf("info:", fd, __VA_ARGS__); \
    
#define prompt(fd, ...) \
    prefixprintf("::", fd, __VA_ARGS__); \

#endif // _UTIL_H
