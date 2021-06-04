void err_quit(char *message);

int create_client_socket(int disable_nagle);
int create_server_socket(int port, int disable_nagle);
void connect_socket(int sockfd, char const *server_address, int server_port);

#ifndef SOCKET_HEADERS
#define SOCKET_HEADERS

#endif