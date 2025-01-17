/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef __sgi
#  define errx(exitcode, format, args...)                                      \
    {                                                                          \
      warnx(format, ##args);                                                   \
      exit(exitcode);                                                          \
    }
#  define warn(format, args...) warnx(format ": %s", ##args, strerror(errno))
#  define warnx(format, args...) fprintf(stderr, format "\n", ##args)
#endif

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif /* HAVE_NETDB_H */
#include <signal.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#include <ctype.h>
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#include <netinet/tcp.h>
#ifndef __sgi
#  include <err.h>
#endif
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>

#define NGHTTP2_NO_SSIZE_T
#include <nghttp2/nghttp2.h>

#include <stdlib.h>
#include <stdio.h>

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define INITIAL_BUFFER_SIZE 4096  // 4 KB buffer size

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
    sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
  }

struct app_context;
typedef struct app_context app_context;

typedef struct http2_stream_data {
  struct http2_stream_data *prev, *next;
  char *request_path;
  int32_t stream_id;
  int fd;
} http2_stream_data;

typedef struct http2_session_data {
  struct http2_stream_data root;
  struct bufferevent *bev;
  app_context *app_ctx;
  nghttp2_session *session;
  char *client_addr;
} http2_session_data;

struct app_context {
  SSL_CTX *ssl_ctx;
  struct event_base *evbase;
};

typedef struct {
  char *buffer;
  size_t buffer_len;
  size_t buffer_capacity;
} request_context;

typedef struct {
    char **components; // Array of strings
    size_t count;      // Number of components
} UriComponents;

typedef struct HeaderNode {
    char *key;
    char *value;
    struct HeaderNode *next;
} HeaderNode;

typedef struct {
  uint8_t presence;
  UriComponents path;
  char *body;
  
} extractions;

// Define the type for HTTP method handlers
// typedef int (*http_handler_t)(const char *path, const char *body, size_t body_len);
typedef int (*http_handler_t)(UriComponents uriComp);

typedef struct {
    http_handler_t handle_get;
    http_handler_t handle_post;
    http_handler_t handle_patch;
    http_handler_t handle_delete;
} server_handler_table_t;

// Each server instance will use its own handler table.
server_handler_table_t handler_table;
static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg);
static void keylog_callback(const SSL *ssl, const char *line);
static nghttp2_ssize file_read_callback(nghttp2_session *session,
                                        int32_t stream_id, uint8_t *buf,
                                        size_t length, uint32_t *data_flags,
                                        nghttp2_data_source *source,
                                        void *user_data);
static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd);
static ssize_t json_read_callback(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source, void *user_data);
static int send_json_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, const char *json_payload);
static SSL_CTX *create_ssl_ctx(const char *key_file, const char *cert_file);
static SSL *create_ssl(SSL_CTX *ssl_ctx);
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data, UriComponents components);
static void add_stream(http2_session_data *session_data,
                       http2_stream_data *stream_data);
static void remove_stream(http2_session_data *session_data,
                          http2_stream_data *stream_data);
static http2_stream_data *
create_http2_stream_data(http2_session_data *session_data, int32_t stream_id);
static void delete_http2_stream_data(http2_stream_data *stream_data);
static http2_session_data *create_http2_session_data(app_context *app_ctx,
                                                     int fd,
                                                     struct sockaddr *addr,
                                                     int addrlen);
static void delete_http2_session_data(http2_session_data *session_data);
static int session_send(http2_session_data *session_data);
static int session_recv(http2_session_data *session_data);
static nghttp2_ssize send_callback(nghttp2_session *session,
                                   const uint8_t *data, size_t length,
                                   int flags, void *user_data);
static int ends_with(const char *s, const char *sub);
static uint8_t hex_to_uint(uint8_t c);
static char *percent_decode(const uint8_t *value, size_t valuelen);
static int error_reply(nghttp2_session *session,
                       http2_stream_data *stream_data);
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data, UriComponents components, HeaderNode *headers);
static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data);
static int check_path(const char *path);
static int on_request_recv(nghttp2_session *session,
                           http2_session_data *session_data,
                           http2_stream_data *stream_data);
static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data);
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data);
static void debug_callback(nghttp2_session *session, const char *msg, size_t len, void *user_data);
static void initialize_nghttp2_session(http2_session_data *session_data);
static int send_server_connection_header(http2_session_data *session_data);
static void readcb(struct bufferevent *bev, void *ptr);
static void writecb(struct bufferevent *bev, void *ptr);
static void eventcb(struct bufferevent *bev, short events, void *ptr);
static void acceptcb(struct evconnlistener *listener, int fd,
                     struct sockaddr *addr, int addrlen, void *arg);
static void start_listen(struct event_base *evbase, const char *service,
                         app_context *app_ctx);
static void initialize_app_context(app_context *app_ctx, SSL_CTX *ssl_ctx,
                                   struct event_base *evbase);
static void run(const char *service, const char *key_file,
                const char *cert_file);
// int main(int argc, char **argv);
int start_server(const char * port, const char *key_file,
                const char *cert_file, server_handler_table_t *handlers);