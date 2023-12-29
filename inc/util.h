#ifndef _UTIL_H
#define _UTIL_H
#include <stdlib.h>

void prefixprintf(char *prefix, int fd, const char *format, ...);

#define fatal(fd, ...)                       \
  do {                                       \
    prefixprintf("fatal:", fd, __VA_ARGS__); \
    exit(-1);                                \
  } while (0);

#define error(fd, ...)                       \
  do {                                       \
    prefixprintf("error:", fd, __VA_ARGS__); \
  } while (0);

#define warning(fd, ...)                         \
  do {                                           \
    char *level = getenv("VERBOSE");             \
    if (level != NULL && level[0] - '0' > 0) {   \
      prefixprintf("warning:", fd, __VA_ARGS__); \
    }                                            \
  } while (0);

#define info(fd, ...)                          \
  do {                                         \
    char *level = getenv("VERBOSE");           \
    if (level != NULL && level[0] - '0' > 1) { \
      prefixprintf("info:", fd, __VA_ARGS__);  \
    }                                          \
  } while (0);

#define prompt(fd, ...)                        \
  do {                                         \
    char *level = getenv("VERBOSE");           \
    if (level != NULL && level[0] - '0' > 2) { \
      prefixprintf("::", fd, __VA_ARGS__);     \
    }                                          \
  } while (0);

#endif  // _UTIL_H
