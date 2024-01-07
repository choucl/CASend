#ifndef _SOCK_H
#define _SOCK_H

#define TIMEOUT 1000000

#include <errno.h>
#include <sys/types.h>

int open_clientfd(char *hostname, char *port) __attribute__((unused));
int open_listenfd(char *port) __attribute__((unused));
ssize_t retry_recv(int sock_fd, void *buf, size_t len, int flags);
ssize_t retry_send(int sock_fd, const void *buf, size_t len, int flags);

#endif
