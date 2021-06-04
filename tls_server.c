#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include "tls_util.h"
#include "socket_util.h"
#include "util.h"

#include <netinet/tcp.h>

void init_openssl()
{
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
  EVP_cleanup();
}

SSL_CTX *create_server_context()
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = SSLv23_server_method();

  ctx = SSL_CTX_new(method);
  if (!ctx)
  {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

void configure_context(SSL_CTX *ctx)
{
  SSL_CTX_set_ecdh_auto(ctx, 1);

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "./cert/cert.pem", SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "./cert/key.pem", SSL_FILETYPE_PEM) <= 0)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }
}

#define READ_BUFFER_SIZE 32768

int main(int argc, char **argv)
{
  int sock;
  SSL_CTX *ctx;

  int server_port = atoi(argv[1]);
  int disable_nagle = atoi(argv[2]);

  init_openssl();
  ctx = create_server_context();

  configure_context(ctx);

  sock = create_server_socket(server_port, disable_nagle);

  SSL_CTX_set_keylog_callback(ctx, (void *)keylogcb);

  /* Handle connections */
  while (1)
  {
    struct sockaddr_in addr;
    uint len = sizeof(addr);
    SSL *ssl;

    long message_length = 16384;

    int client = accept(sock, (struct sockaddr *)&addr, &len);
    if (client < 0)
    {
      perror("Unable to accept");
      exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    if (SSL_accept(ssl) <= 0)
    {
      ERR_print_errors_fp(stderr);
    }
    else
    {
      char *reply = "hello!\n";

      char read_buffer[READ_BUFFER_SIZE] = {};
      int bytes_read = SSL_read(ssl, read_buffer, READ_BUFFER_SIZE);
      SSL_write(ssl, reply, strlen(reply));

      int msg_count = 0;
      while ((bytes_read > 0))
      {
        msg_count++;
        printf("[%d] received data\n", msg_count);

        bytes_read = SSL_read(ssl, read_buffer, READ_BUFFER_SIZE);

        SSL_write(ssl, reply, strlen(reply));
      }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
  }

  printf("shutting down\n");

  close(sock);
  SSL_CTX_free(ctx);
  cleanup_openssl();
}