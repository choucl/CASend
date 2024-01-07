#include "util.h"

#include <stdarg.h>
#include <stdio.h>

void prefixprintf(char *prefix, int fd, const char *format, ...) {
  va_list args;
  va_start(args, format);
  fprintf(stderr, "%-6s ", prefix);
  vfprintf(stderr, format, args);
  if (fd == 0)
    printf("\n");
  else
    printf(" (fd=%d)\n", fd);
  va_end(args);
}
