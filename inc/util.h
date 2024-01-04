#ifndef _UTIL_H
#define _UTIL_H
#include <stdlib.h>
#include <stdio.h>

void prefixprintf(char *prefix, int fd, const char *format, ...);

#define fatal(fd, ...)                       \
  do {                                       \
    prefixprintf("fatal:", fd, __VA_ARGS__); \
    exit(-1);                                \
  } while (0);

#if LOG_LEVEL >= 1
#define error(fd, ...)                       \
  do {                                       \
    prefixprintf("error:", fd, __VA_ARGS__); \
  } while (0);
#else
#define error(fd, ...) asm("")
#endif

#if LOG_LEVEL >= 2
#define warning(fd, ...)                       \
  do {                                         \
    prefixprintf("warning:", fd, __VA_ARGS__); \
  } while (0);
#else
#define warning(fd, ...) asm("")
#endif

#if LOG_LEVEL >= 3
#define info(fd, ...)                       \
  do {                                      \
    prefixprintf("info:", fd, __VA_ARGS__); \
    printf("log level: %d\n", LOG_LEVEL)\
  } while (0);
#else
#define info(fd, ...) asm("")
#endif

#if LOG_LEVEL >= 3
#define prompt(fd, ...)                  \
  do {                                   \
    prefixprintf("::", fd, __VA_ARGS__); \
  } while (0);
#else
#define prompt(fd, ...) asm("")
#endif

#endif  // _UTIL_H
