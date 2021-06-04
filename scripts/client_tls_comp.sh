#!/bin/bash

gcc -o \
  ./exe/client_tls \
  tls_client.c   \
  tls_util.c     \
  socket_util.c  \
	util.c  \
	-lcrypto -lssl
