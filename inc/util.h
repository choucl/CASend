#ifndef _UTIL_H
#define _UTIL_H
#include <stdio.h>
#include <stdlib.h>

void prefixprintf(char *prefix, int fd, const char *format, ...);

#define free0(p) do { free(p); p = NULL; } while (0)

#define prompt(fd, ...)                  \
  do {                                   \
    prefixprintf("::", fd, __VA_ARGS__); \
  } while (0);

#if DEBUG
#define debug(fd, ...)                       \
  do {                                       \
    prefixprintf("debug:", fd, __VA_ARGS__); \
  } while (0);
#else
#define debug(fd, ...) asm("")
#endif

#define fatal(fd, ...)                       \
  do {                                       \
    prefixprintf("fatal:", fd, __VA_ARGS__); \
    exit(-1);                                \
  } while (0);

#if QUIET < 3
#define error(fd, ...)                       \
  do {                                       \
    prefixprintf("error:", fd, __VA_ARGS__); \
  } while (0);
#else
#define error(fd, ...) asm("")
#endif

#if QUIET < 2
#define warning(fd, ...)                       \
  do {                                         \
    prefixprintf("warning:", fd, __VA_ARGS__); \
  } while (0);
#else
#define warning(fd, ...) asm("")
#endif

#if QUIET < 1
#define info(fd, ...)                       \
  do {                                      \
    prefixprintf("info:", fd, __VA_ARGS__); \
  } while (0);
#else
#define info(fd, ...) asm("")
#endif

#endif  // _UTIL_H
