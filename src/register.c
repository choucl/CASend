#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

static void help() {
  printf("%-12s %-24s %-30s\n", "-h", "--help", "show this message");
  printf("%-12s %-24s %-30s\n", "-h", "--force", "force write");
  printf("%-12s %-24s %-30s\n", "-i [ip]", "--server-ip [ip]",
         "specify server domain, default: localhost");
  printf("%-12s %-24s %-30s\n", "-p [port]", "--port [port]",
         "specify server port, default: 8700");
}

int register_config(int argc, char *argv[]) {
  char *host = "localhost", *port = "8700";
  int interactive = 2;
  int force_write = 0;
  const char optstr[] = "hfi:p:";
  const static struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"force", no_argument, 0, 'f'},
      {"server-ip", required_argument, 0, 'i'},
      {"port", required_argument, 0, 'p'}};
  while (1) {
    int c = getopt_long(argc, argv, optstr, long_options, NULL);
    if (c == -1) break;
    switch (c) {
      case 'h':
        printf("CASend Register\n");
        help();
        return 0;
      case 'f':
        force_write = 1;
        break;
      case 'i':
        host = argv[optind - 1];
        interactive--;
        break;
      case 'p':
        port = argv[optind - 1];
        interactive--;
        break;
      default:
        help();
        return -1;
    }
  }

  if (interactive) {
    printf("----------------------------------\n");
    printf("  CASend Register Configuration   \n");
    printf("----------------------------------\n");
    prompt(0, "Please specify server ip, default = localhost");
    printf("-> ");
    host = malloc(sizeof(char) * 32);
    host = fgets(host, 32, stdin);
    host[strlen(host) - 1] = '\0';
    if (host[0] == '\0') {
      sprintf(host, "localhost");
    }
    prompt(0, "Please specify server port, default = 8700");
    printf("-> ");
    port = malloc(sizeof(char) * 6);
    port = fgets(port, 6, stdin);
    port[strlen(port) - 1] = '\0';
    if (port[0] == '\0') {
      sprintf(port, "8700");
    }
  }

  char config_dir[256];
  char config_fname[256];
  strcat(strcpy(config_dir, getenv("HOME")), "/.config/CASend");
  strcat(strcpy(config_fname, config_dir), "/config.txt");
  struct stat st = {0};
  if (stat(config_dir, &st) == -1) {
    mkdir(config_dir, 0777);
    info(0, "Configuration directory created: %s", config_dir);
  }

  if (!force_write && access(config_fname, F_OK) == 0) {
    prompt(0, "Config file already exist, overwrite the config? (y/N)?");
    printf("-> ");
    char reply[2];
    fgets(reply, 2, stdin);
    if (reply[0] != 'y' && reply[0] != 'Y') {
      info(0, "Config file is not overwritten");
      return 0;
    }
  }
  FILE *fp = fopen(config_fname, "w");
  fputs(host, fp);
  fputs("\n", fp);
  fputs(port, fp);
  fputs("\n", fp);
  fclose(fp);
  return 0;
}

int try_read_config(char **host, char **port) {
  char config_fname[256];
  strcat(strcpy(config_fname, getenv("HOME")), "/.config/CASend/config.txt");
  if (access(config_fname, F_OK) == 0) {
    FILE *fp = fopen(config_fname, "r");
    fgets(*host, 256, fp);
    fgets(*port, 256, fp);
    (*host)[strcspn(*host, "\n")] = 0;
    (*port)[strcspn(*port, "\n")] = 0;
    fclose(fp);
    return 0;
  } else {
    return -1;
  }
}
