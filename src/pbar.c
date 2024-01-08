#include "pbar.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t accumulated_sz = 0;
int pbar_exit = 0;
void *progress_bar(void *argp) {
  size_t fsize = (size_t)argp;
  size_t bytes_per_block = fsize / BLOCK_NUM;
  int percentage = 0;
  char pbar_buf[BLOCK_NUM + 10] = {0};
  while (percentage < 100) {
    size_t block_cnt = accumulated_sz / bytes_per_block;
    percentage = accumulated_sz * 100 / fsize;
    pbar_buf[0] = '[';
    for (int i = 0; i < BLOCK_NUM; ++i) {
      pbar_buf[i + 1] = (i < block_cnt) ? '=' : (i == block_cnt) ? '>' : ' ';
    }
    pbar_buf[BLOCK_NUM + 1] = ']';
    pbar_buf[BLOCK_NUM + 2] = ' ';
    sprintf(&pbar_buf[BLOCK_NUM + 3], "%d%%", percentage);
    printf("\r%s", pbar_buf);
    usleep(1000);
    fflush(stdout);
  }
  puts("");
  pbar_exit = 1;
  return 0;
}
