#include "sock.h"

#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int open_clientfd(char *hostname, char *port) {
  int clientfd;
  struct addrinfo hints, *listp, *p;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_NUMERICSERV;
  hints.ai_flags |= AI_ADDRCONFIG;
  int status = getaddrinfo(hostname, port, &hints, &listp);
  if (status != 0) return -1;

  for (p = listp; p; p = p->ai_next) {
    if ((clientfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
      continue;
    if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1) break;
    close(clientfd);
  }

  freeaddrinfo(listp);
  if (!p)
    return -1;
  else
    return clientfd;
}

int open_listenfd(char *port) {
  struct addrinfo hints, *listp, *p;
  int listenfd, optval = 1;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
  hints.ai_flags |= AI_NUMERICSERV;
  int status = getaddrinfo(NULL, port, &hints, &listp);
  if (status != 0) return -1;

  for (p = listp; p; p = p->ai_next) {
    if ((listenfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
      continue;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval,
               sizeof(int));

    if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0) break;
    close(listenfd);
  }

  freeaddrinfo(listp);
  if (!p) return -1;

  if (listen(listenfd, 1024) < 0) {
    close(listenfd);
    return -1;
  }
  return listenfd;
}

ssize_t retry_recv(int sock_fd, void *buf, size_t len, int flags) {
  ssize_t received_len = 0;
  while (received_len != (ssize_t)len) {
    void *recv_buf = (void *)((uintptr_t)buf + received_len);
    ssize_t ret = recv(sock_fd, recv_buf, len - received_len, flags);
    if (ret > 0)
      received_len += ret;
    else {
      if ((ret == -1) && ((errno == EINTR) || (errno == EAGAIN)))
        continue;
      else {
        received_len = ret;
        break;
      }
    }
  }
  return received_len;
}

ssize_t retry_send(int sock_fd, const void *buf, size_t len, int flags) {
  ssize_t sent_len = 0;
  while (sent_len != (ssize_t)len) {
    const void *send_buf = (void *)((uintptr_t)buf + sent_len);
    ssize_t ret = send(sock_fd, send_buf, len - sent_len, flags);
    if (ret > 0)
      sent_len += ret;
    else {
      if ((ret == -1) && ((errno == EINTR) || (errno == EAGAIN)))
        continue;
      else {
        sent_len = ret;
        break;
      }
    }
  }
  return sent_len;
}
