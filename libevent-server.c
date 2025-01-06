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
// #ifdef __sgi
// #  define errx(exitcode, format, args...)                                      \
//     {                                                                          \
//       warnx(format, ##args);                                                   \
//       exit(exitcode);                                                          \
//     }
// #  define warn(format, args...) warnx(format ": %s", ##args, strerror(errno))
// #  define warnx(format, args...) fprintf(stderr, format "\n", ##args)
// #endif

// #ifdef HAVE_CONFIG_H
// #  include <config.h>
// #endif /* HAVE_CONFIG_H */

// #include <sys/types.h>
// #ifdef HAVE_SYS_SOCKET_H
// #  include <sys/socket.h>
// #endif /* HAVE_SYS_SOCKET_H */
// #ifdef HAVE_NETDB_H
// #  include <netdb.h>
// #endif /* HAVE_NETDB_H */
// #include <signal.h>
// #ifdef HAVE_UNISTD_H
// #  include <unistd.h>
// #endif /* HAVE_UNISTD_H */
// #include <sys/stat.h>
// #ifdef HAVE_FCNTL_H
// #  include <fcntl.h>
// #endif /* HAVE_FCNTL_H */
// #include <ctype.h>
// #ifdef HAVE_NETINET_IN_H
// #  include <netinet/in.h>
// #endif /* HAVE_NETINET_IN_H */
// #include <netinet/tcp.h>
// #ifndef __sgi
// #  include <err.h>
// #endif
// #include <string.h>
// #include <errno.h>

// #include <openssl/ssl.h>
// #include <openssl/err.h>
// #include <openssl/conf.h>

// #include <event.h>
// #include <event2/event.h>
// #include <event2/bufferevent_ssl.h>
// #include <event2/listener.h>

// #define NGHTTP2_NO_SSIZE_T
// #include <nghttp2/nghttp2.h>

// #define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

// #define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

// #define INITIAL_BUFFER_SIZE 4096  // 4 KB buffer size

// #define MAKE_NV(NAME, VALUE)                                                   \
//   {                                                                            \
//     (uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,                 \
//     sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,                                   \
//   }

#include "../include/libevent-server.h"

// struct app_context;
// typedef struct app_context app_context;

// typedef struct http2_stream_data {
//   struct http2_stream_data *prev, *next;
//   char *request_path;
//   int32_t stream_id;
//   int fd;
// } http2_stream_data;

// typedef struct http2_session_data {
//   struct http2_stream_data root;
//   struct bufferevent *bev;
//   app_context *app_ctx;
//   nghttp2_session *session;
//   char *client_addr;
// } http2_session_data;

// struct app_context {
//   SSL_CTX *ssl_ctx;
//   struct event_base *evbase;
// };

static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  int rv;
  (void)ssl;
  (void)arg;

  rv = nghttp2_select_alpn(out, outlen, in, inlen);

  if (rv != 1) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  return SSL_TLSEXT_ERR_OK;
}

static void keylog_callback(const SSL *ssl, const char *line) {
    // Get the value of the SSLKEYLOGFILE environment variable
    const char *keylog_file = getenv("SSLKEYLOGFILE");
    if (keylog_file) {
        FILE *fp = fopen(keylog_file, "a"); // Open the log file in append mode
        if (fp) {
            fprintf(fp, "%s\n", line);       // Write the session key
            fclose(fp);                     // Close the file
        } else {
            perror("Failed to open SSLKEYLOGFILE"); // Debugging purposes
        }
    }
}

static nghttp2_ssize file_read_callback(nghttp2_session *session,
                                        int32_t stream_id, uint8_t *buf,
                                        size_t length, uint32_t *data_flags,
                                        nghttp2_data_source *source,
                                        void *user_data) {
  int fd = source->fd;
  ssize_t r;
  (void)session;
  (void)stream_id;
  (void)user_data;

  while ((r = read(fd, buf, length)) == -1 && errno == EINTR)
    ;
  if (r == -1) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  if (r == 0) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return (nghttp2_ssize)r;
}

static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd) {
  int rv;
  nghttp2_data_provider2 data_prd;
  data_prd.source.fd = fd;
  data_prd.read_callback = file_read_callback;

  rv = nghttp2_submit_response2(session, stream_id, nva, nvlen, &data_prd);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

static ssize_t json_read_callback(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source, void *user_data) {
    const char *payload = (const char *)source->ptr;
    size_t payload_len = strlen(payload);

    if (length < payload_len) {
        memcpy(buf, payload, length);
        return length; // Return partial data
    } else {
        memcpy(buf, payload, payload_len);
        *data_flags = NGHTTP2_DATA_FLAG_EOF; // Indicate the end of data
        return payload_len;
    }
}

static int send_json_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, const char *json_payload) {
    int rv;
    nghttp2_data_provider2 data_prd;

    data_prd.source.ptr = json_payload;
    data_prd.read_callback = json_read_callback;

    rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
    if (rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
    }
    return 0;
}

/* Create SSL_CTX. */
static SSL_CTX *create_ssl_ctx(const char *key_file, const char *cert_file) {
  SSL_CTX *ssl_ctx;

  ssl_ctx = SSL_CTX_new(TLS_server_method());
  if (!ssl_ctx) {
    errx(1, "Could not create SSL/TLS context: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                 SSL_OP_NO_COMPRESSION |
                                 SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (SSL_CTX_set1_curves_list(ssl_ctx, "P-256") != 1) {
    errx(1, "SSL_CTX_set1_curves_list failed: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
#else  /* !(OPENSSL_VERSION_NUMBER >= 0x30000000L) */
  {
    EC_KEY *ecdh;
    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh) {
      errx(1, "EC_KEY_new_by_curv_name failed: %s",
           ERR_error_string(ERR_get_error(), NULL));
    }
    SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
    EC_KEY_free(ecdh);
  }
#endif /* !(OPENSSL_VERSION_NUMBER >= 0x30000000L) */

  if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    errx(1, "Could not read private key file %s", key_file);
  }
  if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    errx(1, "Could not read certificate file %s", cert_file);
  }

  SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, NULL);
      // Set the key log callback
    SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);

    // Load the private key and certificate
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        errx(1, "Could not load private key file: %s",
             ERR_error_string(ERR_get_error(), NULL));
    }
    if (SSL_CTX_use_certificate_file(ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        errx(1, "Could not load certificate file: %s",
             ERR_error_string(ERR_get_error(), NULL));
    }

  return ssl_ctx;
}

/* Create SSL object */
static SSL *create_ssl(SSL_CTX *ssl_ctx) {
  SSL *ssl;
  ssl = SSL_new(ssl_ctx);
  if (!ssl) {
    errx(1, "Could not create SSL/TLS session object: %s",
         ERR_error_string(ERR_get_error(), NULL));
  }
  return ssl;
}

// typedef struct {
//   char *buffer;
//   size_t buffer_len;
//   size_t buffer_capacity;
// } request_context;

static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data, UriComponents components) {
    request_context *req_ctx = (request_context *)user_data;

    if (!req_ctx) {
        fprintf(stderr, "Error: user_data (req_ctx) is NULL\n");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    // Allocate buffer if not already allocated
    if (!req_ctx->buffer) {
        req_ctx->buffer = malloc(INITIAL_BUFFER_SIZE);
        if (!req_ctx->buffer) {
            fprintf(stderr, "Error: Failed to allocate buffer\n");
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        req_ctx->buffer_len = 0;
        req_ctx->buffer_capacity = INITIAL_BUFFER_SIZE;
    }

    // Reallocate buffer if necessary
    if (req_ctx->buffer_len + len > req_ctx->buffer_capacity) {
        size_t new_capacity = req_ctx->buffer_capacity * 2;
        while (req_ctx->buffer_len + len > new_capacity) {
            new_capacity *= 2;
        }
        uint8_t *new_buffer = realloc(req_ctx->buffer, new_capacity);
        if (!new_buffer) {
            fprintf(stderr, "Error: Failed to reallocate buffer\n");
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        req_ctx->buffer = new_buffer;
        req_ctx->buffer_capacity = new_capacity;
    }
    fprintf(stderr, "ctx->buffer_len: %zu, len: %zu, ctx->buffer_capacity: %zu\n",
        req_ctx->buffer_len, len, req_ctx->buffer_capacity);
    // Append received data to the buffer
    memcpy(req_ctx->buffer + req_ctx->buffer_len, data, len);
    req_ctx->buffer_len += len;

    fprintf(stderr, "Received data chunk for stream %d: %.*s\n",
            stream_id, (int)len, data);

    // Handle end of data
    if (flags & NGHTTP2_DATA_FLAG_EOF) {
        fprintf(stderr, "End of data. Full payload: %.*s\n",
                (int)req_ctx->buffer_len, req_ctx->buffer);
        // handler_table.handle_get(components);
        // Respond to the client
        // if (send_response(session, stream_id, "200 OK", "application/json",
        //                   "{\"status\":\"received\"}") != 0) {
        //     fprintf(stderr, "Error: Failed to send response\n");
        //     return NGHTTP2_ERR_CALLBACK_FAILURE;
        // }
        // const char *json_payload = "{\"name\": \"DavidJones\", \"Profession\": \"KingOfSea\"}";
          const char *mime_payload =
    "--ADkfLWFKlJPYoEQLUutK\r\n"
    "Content-Type: application/json;\r\n\r\n"
    "{ \"anType\": \"3GPP_ACCESS\", \"dnn\": \"dnn1.slicec1.net\", \"guami\": "
    "{ \"amfId\": \"amf1\", \"plmnId\": { \"mcc\": \"001\", \"mnc\": \"01\" } }, "
    "\"sNssai\": { \"sd\": \"000000\", \"sst\": 1 }, \"servingNetwork\": { "
    "\"mcc\": \"001\", \"mnc\": \"01\" }, \"servingNfId\": "
    "\"e2216bf7-619f-499b-9d9c-6ef8afe50e95\", \"smContextStatusUri\": "
    "\"http://127.0.0.1:65534/smContextStatusUri/amfUeNgapId/1/"
    "pduSessionId/1\", \"supi\": \"001010000000000\" }\r\n"
    "--ADkfLWFKlJPYoEQLUutK\r\n"
    "Content-Type: application/vnd.3gpp.5gnas;\r\n"
    ".\x01\x01\xc1\xff\xff\x91\xa1(\x01\x00U\x04\xc0\xb0\r\n"
    "--ADkfLWFKlJPYoEQLUutK--\r\n";
                char content_length_str[20] = {0};
                // size_t json_length = strlen(json_payload);
                size_t mime_length = strlen(mime_payload);
                snprintf(content_length_str, sizeof(content_length_str), "%zu", mime_length);
                nghttp2_nv hdrs[] = {MAKE_NV(":status", "200"),
                // MAKE_NV("content-type", "application/json")};
                MAKE_NV("content-type", "multipart/related; boundary=\"ADkfLWFKlJPYoEQLUutK\"")};
                // MAKE_NV("content-length", content_length_str)};
        if (send_json_response(session, stream_id, hdrs, ARRLEN(hdrs),
                          mime_payload) != 0) {
            fprintf(stderr, "Error: Failed to send response\n");
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        fprintf(stderr, "Response sent successfully\n");
    }

    return 0;
}


static void add_stream(http2_session_data *session_data,
                       http2_stream_data *stream_data) {
  stream_data->next = session_data->root.next;
  session_data->root.next = stream_data;
  stream_data->prev = &session_data->root;
  if (stream_data->next) {
    stream_data->next->prev = stream_data;
  }
}

static void remove_stream(http2_session_data *session_data,
                          http2_stream_data *stream_data) {
  (void)session_data;

  stream_data->prev->next = stream_data->next;
  if (stream_data->next) {
    stream_data->next->prev = stream_data->prev;
  }
}

static http2_stream_data *
create_http2_stream_data(http2_session_data *session_data, int32_t stream_id) {
  http2_stream_data *stream_data;
  stream_data = malloc(sizeof(http2_stream_data));
  memset(stream_data, 0, sizeof(http2_stream_data));
  stream_data->stream_id = stream_id;
  stream_data->fd = -1;

  add_stream(session_data, stream_data);
  return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
  if (stream_data->fd != -1) {
    close(stream_data->fd);
  }
  free(stream_data->request_path);
  free(stream_data);
}

static http2_session_data *create_http2_session_data(app_context *app_ctx,
                                                     int fd,
                                                     struct sockaddr *addr,
                                                     int addrlen) {
  int rv;
  http2_session_data *session_data;
  SSL *ssl;
  char host[NI_MAXHOST];
  int val = 1;

  ssl = create_ssl(app_ctx->ssl_ctx);
  session_data = malloc(sizeof(http2_session_data));
  memset(session_data, 0, sizeof(http2_session_data));
  session_data->app_ctx = app_ctx;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
  session_data->bev = bufferevent_openssl_socket_new(
    app_ctx->evbase, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
    BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
  rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
                   NI_NUMERICHOST);
  if (rv != 0) {
    session_data->client_addr = strdup("(unknown)");
  } else {
    session_data->client_addr = strdup(host);
  }

  return session_data;
}

static void delete_http2_session_data(http2_session_data *session_data) {
  http2_stream_data *stream_data;
  SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
  fprintf(stderr, "%s disconnected\n", session_data->client_addr);
  if (ssl) {
    SSL_shutdown(ssl);
  }
  bufferevent_free(session_data->bev);
  nghttp2_session_del(session_data->session);
  for (stream_data = session_data->root.next; stream_data;) {
    http2_stream_data *next = stream_data->next;
    delete_http2_stream_data(stream_data);
    stream_data = next;
  }
  free(session_data->client_addr);
  free(session_data);
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data *session_data) {
  int rv;
  rv = nghttp2_session_send(session_data->session);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv2() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int session_recv(http2_session_data *session_data) {
  nghttp2_ssize readlen;
  struct evbuffer *input = bufferevent_get_input(session_data->bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  readlen = nghttp2_session_mem_recv2(session_data->session, data, datalen);
  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    return -1;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0) {
    warnx("Fatal error: evbuffer_drain failed");
    return -1;
  }
  if (session_send(session_data) != 0) {
    return -1;
  }
  return 0;
}

static nghttp2_ssize send_callback(nghttp2_session *session,
                                   const uint8_t *data, size_t length,
                                   int flags, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  struct bufferevent *bev = session_data->bev;
  (void)session;
  (void)flags;

  /* Avoid excessive buffering in server side. */
  if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
      OUTPUT_WOULDBLOCK_THRESHOLD) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  bufferevent_write(bev, data, length);
  return (nghttp2_ssize)length;
}

/* Returns nonzero if the string |s| ends with the substring |sub| */
static int ends_with(const char *s, const char *sub) {
  size_t slen = strlen(s);
  size_t sublen = strlen(sub);
  if (slen < sublen) {
    return 0;
  }
  return memcmp(s + slen - sublen, sub, sublen) == 0;
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c) {
  if ('0' <= c && c <= '9') {
    return (uint8_t)(c - '0');
  }
  if ('A' <= c && c <= 'F') {
    return (uint8_t)(c - 'A' + 10);
  }
  if ('a' <= c && c <= 'f') {
    return (uint8_t)(c - 'a' + 10);
  }
  return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char *percent_decode(const uint8_t *value, size_t valuelen) {
  char *res;

  res = malloc(valuelen + 1);
  if (valuelen > 3) {
    size_t i, j;
    for (i = 0, j = 0; i < valuelen - 2;) {
      if (value[i] != '%' || !isxdigit(value[i + 1]) ||
          !isxdigit(value[i + 2])) {
        res[j++] = (char)value[i++];
        continue;
      }
      res[j++] =
        (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
      i += 3;
    }
    memcpy(&res[j], &value[i], 2);
    res[j + 2] = '\0';
  } else {
    memcpy(res, value, valuelen);
    res[valuelen] = '\0';
  }
  return res;
}

// static nghttp2_ssize file_read_callback(nghttp2_session *session,
//                                         int32_t stream_id, uint8_t *buf,
//                                         size_t length, uint32_t *data_flags,
//                                         nghttp2_data_source *source,
//                                         void *user_data) {
//   int fd = source->fd;
//   ssize_t r;
//   (void)session;
//   (void)stream_id;
//   (void)user_data;

//   while ((r = read(fd, buf, length)) == -1 && errno == EINTR)
//     ;
//   if (r == -1) {
//     return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
//   }
//   if (r == 0) {
//     *data_flags |= NGHTTP2_DATA_FLAG_EOF;
//   }
//   return (nghttp2_ssize)r;
// }

// static int send_response(nghttp2_session *session, int32_t stream_id,
//                          nghttp2_nv *nva, size_t nvlen, int fd) {
//   int rv;
//   nghttp2_data_provider2 data_prd;
//   data_prd.source.fd = fd;
//   data_prd.read_callback = file_read_callback;

//   rv = nghttp2_submit_response2(session, stream_id, nva, nvlen, &data_prd);
//   if (rv != 0) {
//     warnx("Fatal error: %s", nghttp2_strerror(rv));
//     return -1;
//   }
//   return 0;
// }

static const char ERROR_HTML[] = "<html><head><title>404</title></head>"
                                 "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session,
                       http2_stream_data *stream_data) {
  int rv;
  ssize_t writelen;
  int pipefd[2];
  nghttp2_nv hdrs[] = {MAKE_NV(":status", "404")};

  rv = pipe(pipefd);
  if (rv != 0) {
    warn("Could not create pipe");
    rv =
      nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                stream_data->stream_id, NGHTTP2_INTERNAL_ERROR);
    if (rv != 0) {
      warnx("Fatal error: %s", nghttp2_strerror(rv));
      return -1;
    }
    return 0;
  }

  writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
  close(pipefd[1]);

  if (writelen != sizeof(ERROR_HTML) - 1) {
    close(pipefd[0]);
    return -1;
  }

  stream_data->fd = pipefd[0];

  if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
                    pipefd[0]) != 0) {
    close(pipefd[0]);
    return -1;
  }
  return 0;
}


// Function to split a URI into components
UriComponents split_uri(const char *uri) {
    UriComponents result;
    result.components = NULL;
    result.count = 0;

    const char *start = uri;
    const char *end;

    while ((end = strchr(start, '/')) != NULL) {
        if (end != start) { // Non-empty component
            size_t len = end - start;
            char *component = (char *)malloc(len + 1); // Allocate memory
            strncpy(component, start, len);
            component[len] = '\0';

            result.count++;
            result.components = (char **)realloc(result.components, result.count * sizeof(char *));
            result.components[result.count - 1] = component;
        }
        start = end + 1; // Move past the '/'
    }

    // Add the last component if any
    if (*start) {
        size_t len = strlen(start);
        char *component = (char *)malloc(len + 1);
        strcpy(component, start);

        result.count++;
        result.components = (char **)realloc(result.components, result.count * sizeof(char *));
        result.components[result.count - 1] = component;
    }

    return result;
}

// Function to free the allocated memory
void free_uri_components(UriComponents *components) {
    for (size_t i = 0; i < components->count; i++) {
        free(components->components[i]);
    }
    free(components->components);
    components->components = NULL;
    components->count = 0;
}

// Function to create a new header node
HeaderNode *create_header_node(const char *key, size_t key_len, const char *value, size_t value_len) {
    HeaderNode *node = (HeaderNode *)malloc(sizeof(HeaderNode));
    if (!node) {
        perror("Failed to allocate memory for header node");
        exit(EXIT_FAILURE);
    }

    // Allocate memory for key and value
    node->key = (char *)malloc(key_len + 1);
    node->value = (char *)malloc(value_len + 1);

    if (!node->key || !node->value) {
        perror("Failed to allocate memory for key/value");
        free(node);
        exit(EXIT_FAILURE);
    }

    // Copy key and value strings
    strncpy(node->key, key, key_len);
    node->key[key_len] = '\0';  // Null-terminate the key
    strncpy(node->value, value, value_len);
    node->value[value_len] = '\0';  // Null-terminate the value

    printf("Created header node: Key = %s, Value = %s\n", node->key, node->value);

    node->next = NULL;  // Initialize next pointer
    return node;
}

// Function to add a header to the linked list
void add_header(HeaderNode **head, const char *key, size_t key_len, const char *value, size_t value_len) {
    printf("-------------------key:%s\n",key);
    printf("-------------------value:%s\n",value);
    HeaderNode *new_node = create_header_node(key, key_len, value, value_len);
      printf("---------------------b\n");
    new_node->next = *head;
    *head = new_node;
}

// Function to print all headers
void print_headers(HeaderNode *head) {
  printf("--------------------------1\n");
    HeaderNode *current = head;
    printf("--------------------------2\n");
    while (current != NULL){
      printf("--------------------------\n");
        printf("%s: %s\n", current->key, current->value);
        current = current->next;
        printf("--------------------------3\n");
    }
    printf("--------------------------4\n");
}

// Function to free all headers
void free_headers(HeaderNode *head) {
    HeaderNode *current = head;
    while (current) {
        HeaderNode *temp = current;
        current = current->next;

        free(temp->key);
        free(temp->value);
        free(temp);
    }
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data, UriComponents components, HeaderNode *head) {
  fprintf(stderr, "inside on_header_callback\n");
  if (strncmp((const char *)name, "content-length", namelen) == 0) {
        fprintf(stderr, "Content-Length: %.*s\n", (int)valuelen, value);
    } else if (strncmp((const char *)name, "accept", namelen) == 0) {
        fprintf(stderr, "Accept: %.*s\n", (int)valuelen, value);
    } else if (strncmp((const char *)name, "user-agent", namelen) == 0) {
        fprintf(stderr, "User-Agent: %.*s\n", (int)valuelen, value);
    }
  fprintf(stderr, "Header: %.*s: %.*s\n", (int)namelen, name, (int)valuelen, value);
  // HeaderNode *headers = NULL;
  add_header(&head, (const char *)name, namelen, (const char *)value, valuelen);
  // print_headers(head);
  http2_stream_data *stream_data;
  const char PATH[] = ":path";
  const char METHOD[] = ":method";
  (void)flags;
  (void)user_data;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
  fprintf(stderr, "inside case\n");
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      fprintf(stderr, "inside frame->headers.cat != NGHTTP2_HCAT_REQUEST\n");
      break;
    }
    stream_data =
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!stream_data || stream_data->request_path) {
      fprintf(stderr, "!stream_data || stream_data->request_path\n");
      break;
    }

    // Detect the :path header
    if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
      fprintf(stderr, "Detected :path header\n");
      // UriComponents components = split_uri((const char *)value);
      components = split_uri((const char *)value);
      printf("URI components:\n");
    for (size_t i = 0; i < components.count; i++) {
        printf("%s\n", components.components[i]);
    }
      size_t j;
      for (j = 0; j < valuelen && value[j] != '?'; ++j)
        ;
      stream_data->request_path = percent_decode(value, j);
    }

    // Detect the :method header
    if (namelen == sizeof(METHOD) - 1 && memcmp(METHOD, name, namelen) == 0) {
      fprintf(stderr, "Detected :method header\n");
      if (valuelen == 4 && memcmp("POST", value, 4) == 0) {
        fprintf(stderr, "POST request detected\n");
        // return handler_table.handle_get(PATH, NULL, 0); // Call the handler
      }
    }
    break;
  }
  return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  fprintf(stderr, "inside on_begin_header_callback");
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                       stream_data);
  if (frame->hd.type == NGHTTP2_HEADERS &&
        frame->headers.cat == NGHTTP2_HCAT_REQUEST &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        fprintf(stderr, "Received all data in HEADERS frame\n");
        // Process payload from headers here
    }   
  return 0;
}

/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char *path) {
  /* We don't like '\' in url. */
  return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
         strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
         !ends_with(path, "/..") && !ends_with(path, "/.");
}

static int on_request_recv(nghttp2_session *session,
                           http2_session_data *session_data,
                           http2_stream_data *stream_data) {
  int fd;
  nghttp2_nv hdrs[] = {MAKE_NV(":status", "200")};
  char *rel_path;

  if (!stream_data->request_path) {
    if (error_reply(session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  fprintf(stderr, "%s GET %s\n", session_data->client_addr,
          stream_data->request_path);
  if (!check_path(stream_data->request_path)) {
    if (error_reply(session, stream_data) != 0) {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
  }
  for (rel_path = stream_data->request_path; *rel_path == '/'; ++rel_path)
    ;
  // fd = open(rel_path, O_RDONLY);
  fd = open(rel_path, 0);  
  // if (fd == -1) {
  //   if (error_reply(session, stream_data) != 0) {
  //     return NGHTTP2_ERR_CALLBACK_FAILURE;
  //   }
  //   return 0;
  // }
  stream_data->fd = fd;

  // if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs), fd) !=
  //     0) {
  //   close(fd);
  //   return NGHTTP2_ERR_CALLBACK_FAILURE;
  // }
  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  switch (frame->hd.type) {
  case NGHTTP2_DATA:
    fprintf(stderr, "Data frame received for stream ID %d\n", frame->hd.stream_id);
  case NGHTTP2_HEADERS:
    /* Check that the client request has finished */
    fprintf(stderr, "Headers frame received for stream ID %d\n", frame->hd.stream_id);
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream_data =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
      if (!stream_data) {
        return 0;
      }
      return on_request_recv(session, session_data, stream_data);
    }
    break;
  default:
    break;
  }
  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  (void)error_code;

  stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!stream_data) {
    return 0;
  }
  remove_stream(session_data, stream_data);
  delete_http2_stream_data(stream_data);
  return 0;
}

// Debug callback function
static void debug_callback(nghttp2_session *session, const char *msg, size_t len, void *user_data) {
    fprintf(stderr, "NGHTTP2 DEBUG:\n");
    // fprintf(stderr, "NGHTTP2 DEBUG: %.*s\n", (int)len, msg);
}

static void initialize_nghttp2_session(http2_session_data *session_data) {
  nghttp2_session_callbacks *callbacks;
  HeaderNode *head = NULL;
  UriComponents components;

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
    callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
    callbacks, on_begin_headers_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
  fprintf(stderr, "on_data_chunk_recv_callback registered\n");
  // Set the debug callback
    nghttp2_session_callbacks_set_error_callback2(callbacks, debug_callback);
  nghttp2_session_server_new(&session_data->session, callbacks, session_data);
  fprintf(stderr, "server new\n");

  nghttp2_session_callbacks_del(callbacks);
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data *session_data) {
  nghttp2_settings_entry iv[1] = {
    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/* readcb for bufferevent after client connection header was
   checked. */
static void readcb(struct bufferevent *bev, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  (void)bev;

  if (session_recv(session_data) != 0) {
    delete_http2_session_data(session_data);
    return;
  }
}

/* writecb for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. If the
   connection is not going to shutdown, we call session_send() to
   process pending data in the output buffer. This is necessary
   because we have a threshold on the buffer size to avoid too much
   buffering. See send_callback(). */
static void writecb(struct bufferevent *bev, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    return;
  }
  if (nghttp2_session_want_read(session_data->session) == 0 &&
      nghttp2_session_want_write(session_data->session) == 0) {
    delete_http2_session_data(session_data);
    return;
  }
  if (session_send(session_data) != 0) {
    delete_http2_session_data(session_data);
    return;
  }
}

/* eventcb for bufferevent */
static void eventcb(struct bufferevent *bev, short events, void *ptr) {
  http2_session_data *session_data = (http2_session_data *)ptr;
  if (events & BEV_EVENT_CONNECTED) {
    const unsigned char *alpn = NULL;
    unsigned int alpnlen = 0;
    SSL *ssl;
    (void)bev;

    fprintf(stderr, "%s connected\n", session_data->client_addr);

    ssl = bufferevent_openssl_get_ssl(session_data->bev);

    SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);

    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
      fprintf(stderr, "%s h2 is not negotiated\n", session_data->client_addr);
      delete_http2_session_data(session_data);
      return;
    }

    initialize_nghttp2_session(session_data);

    if (send_server_connection_header(session_data) != 0 ||
        session_send(session_data) != 0) {
      delete_http2_session_data(session_data);
      return;
    }

    return;
  }
  if (events & BEV_EVENT_EOF) {
    fprintf(stderr, "%s EOF\n", session_data->client_addr);
  } else if (events & BEV_EVENT_ERROR) {
    fprintf(stderr, "%s network error\n", session_data->client_addr);
  } else if (events & BEV_EVENT_TIMEOUT) {
    fprintf(stderr, "%s timeout\n", session_data->client_addr);
  }
  delete_http2_session_data(session_data);
}

/* callback for evconnlistener */
static void acceptcb(struct evconnlistener *listener, int fd,
                     struct sockaddr *addr, int addrlen, void *arg) {
  app_context *app_ctx = (app_context *)arg;
  http2_session_data *session_data;
  (void)listener;

  session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

  bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);
}

static void start_listen(struct event_base *evbase, const char *service,
                         app_context *app_ctx) {
  int rv;
  struct addrinfo hints;
  struct addrinfo *res, *rp;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

  rv = getaddrinfo(NULL, service, &hints, &res);
  if (rv != 0) {
    errx(1, "Could not resolve server address");
  }
  for (rp = res; rp; rp = rp->ai_next) {
    struct evconnlistener *listener;
    listener = evconnlistener_new_bind(
      evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 16,
      rp->ai_addr, (int)rp->ai_addrlen);
    if (listener) {
      freeaddrinfo(res);

      return;
    }
  }
  errx(1, "Could not start listener");
}

static void initialize_app_context(app_context *app_ctx, SSL_CTX *ssl_ctx,
                                   struct event_base *evbase) {
  memset(app_ctx, 0, sizeof(app_context));
  app_ctx->ssl_ctx = ssl_ctx;
  app_ctx->evbase = evbase;
}

static void run(const char *service, const char *key_file,
                const char *cert_file) {
  SSL_CTX *ssl_ctx;
  app_context app_ctx;
  struct event_base *evbase;

  ssl_ctx = create_ssl_ctx(key_file, cert_file);
  evbase = event_base_new();
  initialize_app_context(&app_ctx, ssl_ctx, evbase);
  start_listen(evbase, service, &app_ctx);

  event_base_loop(evbase, 0);

  event_base_free(evbase);
  SSL_CTX_free(ssl_ctx);
}

// int main(int argc, char **argv) {
//   struct sigaction act;

//   if (argc < 4) {
//     fprintf(stderr, "Usage: libevent-server PORT KEY_FILE CERT_FILE\n");
//     exit(EXIT_FAILURE);
//   }

//   memset(&act, 0, sizeof(struct sigaction));
//   act.sa_handler = SIG_IGN;
//   sigaction(SIGPIPE, &act, NULL);

//   run(argv[1], argv[2], argv[3]);
//   return 0;
// }

int start_server(const char * port, const char *key_file,
                const char *cert_file, server_handler_table_t *handlers) {
  memcpy(&handler_table, handlers, sizeof(server_handler_table_t));
  struct sigaction act;

  // if (argc < 4) {
  //   fprintf(stderr, "Usage: libevent-server PORT KEY_FILE CERT_FILE\n");
  //   exit(EXIT_FAILURE);
  // }

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);

  run(port, key_file, cert_file);
  return 0;
}