#include <stdarg.h>
#include <stdio.h>
#include "util.h"

void prefixprintf(char *prefix, int fd, const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "%-10s (fd = %d) ", prefix, fd);
    vfprintf(stderr, format, args);
    printf("\n");
    va_end(args);
}
