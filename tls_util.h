#include <openssl/ssl.h>
#include <openssl/err.h>

#define KEYLOG_FILE "./keys/keyfile" // where program puts the keys

/* Protocol message types */
#define PROT_TYPE_CLIENT_HELLO 1 
#define PROT_TYPE_SERVER_HELLO 2 
#define PROT_TYPE_NEW_SN_TICK 4
#define PROT_TYPE_ENCRYPT_EXT 8
#define PROT_TYPE_CERT 11
#define PROT_TYPE_CERT_VERIFY 15 
#define PROT_TYPE_FINISHED 20 
#define PROT_TYPE_REKEY 24 

/* Content types */
#define CONT_TYPE_HANDSHAKE 22

#define READ_BUFFER_SIZE 32768

typedef struct
{
  uint64_t rekey_serv_count;
  uint64_t rekey_cli_count;
} TLSstatistics;

typedef struct
{
  uint8_t handshake_type;
  uint32_t msg_len;
  const uint8_t *msg;
} Handshake;

SSL *setup_tls();
SSL_CTX *create_context();
void cleanup_tls();

void tls_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
SSL_CTX_keylog_cb_func keylogcb(const SSL *ssl, const char *line);

Handshake *get_handshake_msg(const uint8_t *bytes, size_t len);

void print_bytes_f(const uint8_t *bytes, size_t len);
void print_proto_handshake(Handshake *handshake_msg);
void print_proto_bytes();
char *get_handshake_type_name(const uint8_t handshake_type);
int read_tls_data(int print_read_info);
void write_tls_data(char *data, int data_len, int print_write_info);

TLSstatistics *get_stats_struct();
void update_session_stats(int write_p, Handshake *handshake_msg);

void send_key_update();
void send_rcv_key_update();