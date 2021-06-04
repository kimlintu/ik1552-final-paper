#include <stdio.h>
#include <string.h>
#include "tls_util.h"

TLSstatistics *stats;
SSL *ssl;
SSL_CTX *ctx;

long last_sent_time = -1, last_read_time = -1;

SSL *setup_tls()
{
  OpenSSL_add_ssl_algorithms();

  ctx = create_context();
  ssl = SSL_new(ctx);

  /* Callbacks */
  SSL_CTX_set_keylog_callback(ctx, (void *)keylogcb);
  SSL_set_msg_callback(ssl, (void *)tls_msg_callback);

  /* Initialize statistics struct */
  stats = malloc(sizeof(TLSstatistics));
  stats->rekey_serv_count = 0;
  stats->rekey_cli_count = 0;

  return ssl;
}

void cleanup_tls()
{
  SSL_shutdown(ssl);
  SSL_free(ssl);

  SSL_CTX_free(ctx);

  EVP_cleanup();

  free(stats);
}

/**
 * 
 * Summary: 
 *  Creates and returns the context that will be used in the exchange
 * 
 * OpenSSL documentation: 
 *  https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_new.html
 * 
 **/
SSL_CTX *create_context()
{
  const SSL_METHOD *method = SSLv23_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);

  if (!ctx)
  {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

/**
 * 
 * Summary: 
 *  Prints the handshake-established secrets to a file.
 *  Gets invoked whenever TLS key material is generated or received.
 * 
 * OpenSSL documentation: 
 *  https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_keylog_callback.html
 * 
 **/
SSL_CTX_keylog_cb_func keylogcb(const SSL *ssl, const char *line)
{
  SSL_SESSION *session_id = SSL_get_session(ssl);

  FILE *fp;
  fp = fopen(KEYLOG_FILE, "a");
  BIO *file = BIO_new_fp(fp, BIO_NOCLOSE);

  BIO_write(file, line, strlen(line));
  BIO_write(file, "\n", 1);

  fclose(fp);
}

/**
 * 
 * Summary: 
 *  Prints information about any received handshake/protocol messages and also updates
 *  session statistics relating to the message.
 *  Gets invoked whenever a TLS handshake/protocol message is sent or received.
 * 
 * OpenSSL documentation: 
 *  https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_set_msg_callback.html
 * 
 **/
void tls_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{

  if (content_type != 256 && content_type != 257)
  {
    printf("\n------------------------------------\n\n\n");
    // write_p == 0 -> protocol msg received
    // write_p == 1 -> protocol msg transmitted
    if (write_p == 0)
    {
      printf("Protocol message [RECEIVED]\n");
    }
    else if (write_p == 1)
    {
      printf("Protocol message [TRANSMITTED]\n");
    }

    switch (content_type)
    {
    case CONT_TYPE_HANDSHAKE:;
      //print_proto_header(version, content_type, buf, len);

      Handshake *handshake_msg = get_handshake_msg((const uint8_t *)buf, len);
      update_session_stats(write_p, handshake_msg);
      print_proto_handshake(handshake_msg);
      free(handshake_msg);
      break;
    default:
      break;
    }

    printf("\n");
  }
}

/**
 * 
 * Summary: 
 *  Reads bytes of a handshake/protocol message read in the message callback, 
 *  formats them in a Handshake struct, and returns the struct.
 * 
 *  OpenSSL documentation (msg callback): https://www.openssl.org/docs/man1.1.0/man3/SSL_CTX_set_msg_callback.html
 * 
 **/
Handshake *get_handshake_msg(const uint8_t *bytes, size_t len)
{
  // First byte is handshake type.
  const uint8_t handshake_type = bytes[0];

  // Following three bytes is length of handshake data.
  const uint32_t msg_len = ((bytes[1] << 2) | (bytes[2] << 1)) | (uint32_t)bytes[3];

  // Remaining (data_len) bytes is the protocol message data.

  Handshake *handshake_msg = malloc(sizeof(Handshake));

  handshake_msg->handshake_type = handshake_type;
  handshake_msg->msg_len = msg_len;
  handshake_msg->msg = (bytes + 4);

  return handshake_msg;
}

/**
 * 
 * Summary: 
 *  Returns the string representation of the handshake_type byte.
 * 
 *  Hanshake types: https://datatracker.ietf.org/doc/html/rfc8446#section-4
 * 
 **/

char *get_handshake_type_name(const uint8_t handshake_type)
{
  switch (handshake_type)
  {
  case PROT_TYPE_CLIENT_HELLO:
    return "Client hello";
    break;
  case PROT_TYPE_SERVER_HELLO:
    return "Server hello";
    break;
  case PROT_TYPE_NEW_SN_TICK:
    return "New session ticket";
    break;
  case PROT_TYPE_ENCRYPT_EXT:
    return "Encrypted extensions";
    break;
  case PROT_TYPE_CERT:
    return "Certificate";
    break;
  case PROT_TYPE_CERT_VERIFY:
    return "Certificate verification";
    break;
  case PROT_TYPE_FINISHED:
    return "Finished";
    break;
  case PROT_TYPE_REKEY:
    return "Key update";
    break;
  default:
    return "Not defined";
  }
}

/**
 * 
 * Summary: 
 *  Formats and prints the provided bytes of length len.
 * 
 **/
void print_bytes_f(const uint8_t *bytes, size_t len)
{
  int i;

  printf("|");
  for (i = 0; i < len; i++)
  {
    char *str = ((((i + 1) % 12) == 0) ? " %02x |\n|" : " %02x |");
    printf(str, *(bytes + i));
  }
}

/**
 * 
 * Summary: 
 *  Prints the handshake/protocol message contained in handshake_msg.
 * 
 **/
#include <sys/time.h>

void print_proto_handshake(Handshake *handshake_msg)
{
  struct timespec time_of_message;
  clock_gettime(CLOCK_REALTIME, &time_of_message);

  printf("[HANDSHAKE MESSAGE]\n");
  printf("handshake_type: %d (%s)\n", handshake_msg->handshake_type, get_handshake_type_name(handshake_msg->handshake_type));
  printf("data_len: %d\n", handshake_msg->msg_len);
  printf("data: \n");
  print_bytes_f(handshake_msg->msg, handshake_msg->msg_len);
  printf("\ntime: %ld\n", (time_of_message.tv_sec * 1000 + time_of_message.tv_nsec / 1000000));
  printf("\n\n");
}

/**
 * 
 * Summary: 
 *  Updates relevant statistics based on the provided handshake message.
 * 
 **/
void update_session_stats(int write_p, Handshake *handshake_msg)
{
  switch (handshake_msg->handshake_type)
  {
  case PROT_TYPE_REKEY:
    if (write_p == 0)
      stats->rekey_serv_count += 1;
    else if (write_p == 1)
      stats->rekey_cli_count += 1;
    break;
  }
}

/**
 * 
 * Summary: 
 *  Tries to read data from the TLS socket. If printe_read_info is 1, 
 *  the amount of bytes read and time since last read will be printed.
 *  Returns the amount of bytes read.
 * 
 **/
int read_tls_data(int print_read_info)
{
  struct timespec time_of_message;
  clock_gettime(CLOCK_REALTIME, &time_of_message);
  long time_in_ms = (time_of_message.tv_sec * 1000 + time_of_message.tv_nsec / 1000000);

  char read_buffer[READ_BUFFER_SIZE];

  int bytes_read = SSL_read(ssl, read_buffer, READ_BUFFER_SIZE);

  if (print_read_info == 1)
  {
    printf("------------------------------------------------\n");
    printf("read %d bytes at %ldms\n", bytes_read, time_in_ms);
    if (last_sent_time != -1)
      printf("\n%ldms since last read\n", (time_in_ms - last_sent_time));
  }
  
  last_sent_time = time_in_ms;

  return bytes_read;
}

void write_tls_data(char *data, int data_len, int print_write_info)
{
  struct timespec time_of_message;
  clock_gettime(CLOCK_REALTIME, &time_of_message);
  long time_in_ms = (time_of_message.tv_sec * 1000 + time_of_message.tv_nsec / 1000000);

  int write_status = SSL_write(ssl, (void *)data, data_len);

  if (print_write_info == 1)
  {
    printf("------------------------------------------------\n");
    printf("sent %d bytes at %ldms\n\n", write_status, time_in_ms);
    if (last_read_time != -1)
      printf("%ldms since last send\n", (time_in_ms - last_read_time));
  }

  last_read_time = time_in_ms;

  if (write_status < 0)
  {
    printf("error");
  }
}

TLSstatistics *get_stats_struct()
{
  return stats;
}

void send_key_update()
{
  SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED);
}

void send_rcv_key_update()
{
  SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED);
}
