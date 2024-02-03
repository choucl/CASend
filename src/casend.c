#include <string.h>

#include "config.h"
#include "receiver.h"
#include "sender.h"
#include "util.h"

void help() {
  printf("CASend - Safe and simple file transfer tool\n");
  printf("Usage:\n");
  printf("  casend send/receive [flags]\n");
}

int main(int argc, char *argv[]) {
  char *type = argv[1];
  if (!type) {
    help();
    return -1;
  }
  if (strncmp(type, "-h", 2) == 0 || strncmp(type, "--help", 6) == 0) {
    help();
    return 0;
  } else if (strncmp(type, "send", 4) == 0) {
    // send
    return send_handler(argc - 1, &argv[1]);
  } else if (strncmp(type, "receive", 7) == 0) {
    // receive
    return receive_handler(argc - 1, &argv[1]);
  } else {
    help();
    fatal(0, "Invalid subcommand: %s", type);
  }
}
