#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>

#include "socket_util.h"

void err_quit(char *message)
{
  printf("%s\n", message);

  exit(-1);
}

int create_server_socket(int port, int disable_nagle)
{
  int s;
  struct sockaddr_in addr;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  s = socket(AF_INET, SOCK_STREAM, 0);

  /* Disable Nagle's algorithm */
  if (disable_nagle != 0)
  {
    int v = 1;
    if ((setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(int))) < 0)
      err_quit("could not disable nagle");
  }

  if (s < 0)
  {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }

  if (listen(s, 1) < 0)
  {
    perror("Unable to listen");
    exit(EXIT_FAILURE);
  }

  return s;
}

int create_client_socket(int disable_nagle)
{
  int sockfd;
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    err_quit("could not create socket");

  // Configure receive timeout
  struct timeval timeout;
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;

  if ((setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout))) < 0)
    err_quit("could not set socket timeout");

  /* Disable Nagle's algorithm */
  if (disable_nagle != 0)
  {
    int v = 1;
    if ((setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(int))) < 0)
      err_quit("could not disable nagle");
  }

  return sockfd;
}

void connect_socket(int sockfd, char const *server_address, int server_port)
{
  struct sockaddr_in servaddr;

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET; // address family for server (AF_INET = IPv4)
  servaddr.sin_port = htons(server_port);

  if (inet_pton(AF_INET, server_address, &servaddr.sin_addr) <= 0) // translate IPv4 address from dotted decimal to binary
    err_quit("inet_pton error for given address");

  if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) // bind socket between local address and peer address
    err_quit("connect error");
}