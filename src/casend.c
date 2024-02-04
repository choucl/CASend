#include <string.h>

#include "config.h"
#include "receiver.h"
#include "sender.h"
#include "register.h"
#include "util.h"

void help() {
  printf("CASend - Safe and simple file transfer tool\n");
  printf("Usage:\n");
  printf("  casend <subcommand> [flags]\n");
  printf("Subcommands:\n");
  printf("  send     - send a file\n");
  printf("  receive  - receiver a file with given code\n");
  printf("  register - register the server configuration\n");
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
  } else if (strncmp(type, "register", 8) == 0) {
    // register
    return register_config(argc - 1, &argv[1]);
  } else {
    help();
    fatal(0, "Invalid subcommand: %s", type);
  }
}
