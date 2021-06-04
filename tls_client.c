#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "tls_client.h"
#include "tls_util.h"
#include "socket_util.h"

#include "util.h"

#define HTTP_REQUEST_AMT 1000000

#define HTTP_PRINT_RESPONSE 0 // 1 = print response, \
                              // 0 = dont print

#define TEST_TIME_LIMITED 0 // 1 = test is time limited \
                            // 0 = test is limited by HTTP_REQUEST_AMT

void print_test_info(TestInfo *test_info)
{
  printf("\nrequests: %ld of max %ld\n", test_info->request_count, test_info->request_limit);

  printf("time passed: %ld seconds\n", test_info->time_passed);
  printf("time left: %ld\n", (test_info->time_limit - test_info->time_passed));

  double completion = (double)test_info->time_passed / test_info->time_limit;
  printf("completion: %f\n", completion);
}

/**
 * Main program
 * 
 **/
int main(int argc, char const *argv[])
{
  const char *server_ip = argv[1];
  const char *server_port = argv[2];
  int size = atoi(argv[3]);                     // 1 == big, 0 == small
  int key_update_request = atoi(argv[4]); // 1 or 0
  int disable_nagles = atoi(argv[5]);     // 1 or 0

  printf("\n--------START SESSION-----------\n");
  time_t session_start = time(NULL);

  SSL *ssl = setup_tls();

  /* Socket setup */
  int sockfd = create_client_socket(disable_nagles);
  connect_socket(sockfd, server_ip, atoi(server_port));

  SSL_set_fd(ssl, sockfd); // Configure TLS to pass through created socket.

  int connection_status = SSL_connect(ssl); // Setup TLS connection to server.
  if (connection_status < 0)
  {
    // TLS handshake was not successfull, report error
    // TODO
    printf("HANDSHAKE ERROR\n");
  }

  /***************** START OF TEST *******************/
  TestInfo *test = malloc(sizeof(TestInfo));
  test->bytes_count = 0;
  test->request_count = 0;
  test->request_limit = 10000;
  test->time_limit = 25;
  test->time_passed = 0;
  test->print_info_interval = 10; // Print session info every 10 seconds

  int last_requests = 0;

  int running = 1;

  test->start_time = time(NULL);
  time_t last_time = test->start_time;
  while ((test->time_passed < test->time_limit) && (test->request_count < test->request_limit))
  {
    // Send HTTPS request
    int len;
    if (size == 0)
      len = 512;
    else if (size == 1)
      len = 8192;
    else
      err_quit("invalid size value.");

    char data[len];
    create_message(data, len);
    write_tls_data(data, len, 1);

    // Read response
    int bytes_read = read_tls_data(1);
    test->bytes_count += bytes_read;

    if (bytes_read < 0)
    {
      // READ ERROR, report error
      // TODO
    }

    test->request_count++;

    time_t duration = (time(NULL) - last_time);
    if (duration >= test->print_info_interval)
    {
      if (key_update_request == 0)
      {
        printf("sending key update, update not requested");

        send_key_update();
      }
      else if (key_update_request == 1)
      {
        printf("sending key update, update requested");

        send_rcv_key_update();
      }

      //print_test_info(test);

      /*
      int requests_sent = test->request_count - last_requests;
      double speed = (double)requests_sent / duration;
      printf("sending speed: %f requests per second\n", speed);
      */

      last_requests = test->request_count;
      last_time = time(NULL);
    }

    test->time_passed = time(NULL) - test->start_time;
  }

  time_t finished_time = time(NULL) - test->start_time;

  TLSstatistics *stats = get_stats_struct();

  printf("\n\n[AFTER SESSION]\n\n");
  printf("\n\n");
  printf("http requests: %ld\n", test->request_count);
  printf("bytes read: %ld\n", test->bytes_count);
  printf("SERVER REKEY COUNT: %ld\n", stats->rekey_serv_count);
  printf("CLIENT REKEY COUNT: %ld\n", stats->rekey_cli_count);
  printf("TOTAL  REKEY COUNT: %ld\n", (stats->rekey_serv_count + stats->rekey_cli_count));

  printf("\nSECONDS: %ld (%ld minutes)\n", finished_time, (finished_time / 60));

  // Cleanup

  cleanup_tls();

  close(sockfd);

  free(test);

  printf("\n--------END SESSION-----------\n");

  return 0;
}