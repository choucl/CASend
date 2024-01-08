#ifndef _PBAR_H
#define _PBAR_H

#include <stdlib.h>

#define BLOCK_NUM 40
extern size_t accumulated_sz;
extern int pbar_exit;
void *progress_bar(void *argp);

#endif
