#!/bin/bash

gcc -o \
  ./exe/server_tls \
  tls_server.c   \
	tls_util.c  \
  util.c  \
  socket_util.c \
  -lcrypto -lssl
