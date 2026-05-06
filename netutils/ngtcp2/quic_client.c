/****************************************************************************
 * apps/netutils/ngtcp2/quic_client.c
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <uv.h>

/* Peer address: IPv4 or IPv6 literal (no DNS). Change REMOTE_ADDR / REMOTE_PORT. */
#define REMOTE_ADDR "192.168.0.142"
#define REMOTE_PORT "8888"
#define ALPN "\x2h3"
#define MESSAGE "GET /\r\n"

/*
 * User data in a ngtcp2 connection
 */
struct client {
    ngtcp2_crypto_conn_ref conn_ref;
    int fd;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    WOLFSSL_CTX *ssl_ctx; // TODO : replace with wolfssl context
    SSL *ssl; // TODO : replace with wolfssl ssl object
    ngtcp2_conn *conn;

    struct {
        int64_t stream_id;
        const uint8_t *data;
        size_t datalen;
        size_t nwrite;
    } stream;

    ngtcp2_ccerr last_error;

    uv_poll_t handle;
    uv_timer_t timer;
};

/*
 * Utils
 */
static int numeric_host_family(const char *hostname, int family) {
    uint8_t dst[sizeof(struct in6_addr)];
    return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char *hostname) {
    return numeric_host_family(hostname, AF_INET) ||
           numeric_host_family(hostname, AF_INET6);
}

static uint64_t timestamp(void) {
    struct timespec tp;

    if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
        fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Return nanoseconds
    return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void log_printf(void *user_data, const char *fmt, ...) {
    va_list ap;
    (void)user_data;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

/*
 * Initialization
 */
static int create_sock(struct sockaddr *remote_addr, socklen_t *remote_len,
    const char *addr, const char *port) {
    struct addrinfo hints = {0};
    struct addrinfo *res, *rp;
    int rv, fd = -1;

    hints.ai_flags = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (numeric_host(addr)) {
        /* Numeric IP only — no name resolution. */
        hints.ai_flags |= AI_NUMERICHOST;
    }

    rv = getaddrinfo(addr, port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo() returned %s\n", gai_strerror(rv));
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd > 0)
            break;
    }

    if (fd > 0) {
        *remote_len = rp->ai_addrlen;
        memcpy(remote_addr, rp->ai_addr, rp->ai_addrlen);
    }

    freeaddrinfo(res);

    return fd;
}

static int connect_sock(struct sockaddr *local_addr, socklen_t *local_addrlen, 
                        int fd, struct sockaddr *remote_addr, 
                        socklen_t *remote_addrlen) {

    if (connect(fd, remote_addr, *remote_addrlen) == -1) {
        fprintf(stderr, "connect() failed : %s\n", strerror(errno));
        return -1;
    }

    if (getsockname(fd, local_addr, local_addrlen) == -1) {
        fprintf(stderr, "getsockname failed : %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int verify_callback(int mode, WOLFSSL_X509_STORE_CTX* ctx)
{
    // Seems like non-zero is considered as success
    return 1;
}

static int client_ssl_init(struct client *c) {

    // Get the TLS 1.3 method
    WOLFSSL_METHOD* method = TLS_client_method();
    if (!method) {
        fprintf(stderr, "could not get TLS client method\n");
        return -1;
    }

    // Create a new SSL context taking a SSL/TLS protocol as input.
    c->ssl_ctx = wolfSSL_CTX_new(method);
    if (!c->ssl_ctx) {
        fprintf(stderr, "wolfSSL_CTX_new() failed.\n");
        return -1;
    }

    // Certificate verifier
    wolfSSL_CTX_set_verify(c->ssl_ctx, WOLFSSL_VERIFY_NONE, NULL);

    // Set the minimum&maximum TLS version to 1.3.
    // Sets WOLFSSL_QUIC_METHOD by calling wolfSSL_CTX_set_quic_method.
    if (ngtcp2_crypto_wolfssl_configure_client_context(c->ssl_ctx) != 0) {
        fprintf(stderr, "ngtcp2_crypto_wolfssl_configure_client_context() failed\n");
        return -1;
    }

    int ret = wolfSSL_CTX_set_cipher_list(c->ssl_ctx,
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    printf("RET OF wolfSSL_CTX_set_cipher_list is %d\n", ret);

    int groups[] = {
        WOLFSSL_ECC_X25519,
        WOLFSSL_ECC_SECP256R1,
        WOLFSSL_ECC_SECP384R1,
        WOLFSSL_ECC_SECP521R1,
    };
    ret = wolfSSL_CTX_set_groups(c->ssl_ctx, groups, (int)(sizeof(groups) / sizeof(groups[0])));
    printf("RET OF wolfSSL_CTX_set_groups is %d\n", ret);

    // Create a new SSL session based on the existing context.
    c->ssl = wolfSSL_new(c->ssl_ctx);
    if (!c->ssl) {
        fprintf(stderr, "wolfSSL_new() failed.\n");
        return -1;
    }

    ret = wolfSSL_CTX_set_groups(c->ssl_ctx, groups, (int)(sizeof(groups) / sizeof(groups[0])));
    printf("RET OF wolfSSL_CTX_set_groups is %d\n", ret);

    wolfSSL_set_app_data(c->ssl, &c->conn_ref);
    wolfSSL_set_connect_state(c->ssl);
    ret = wolfSSL_set_alpn_protos(c->ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);
    if(ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_set_alpn_protos failed : %d\n", ret);
        //return -1;
    }
    if (!numeric_host(REMOTE_ADDR)) {
        wolfSSL_set_tlsext_host_name(c->ssl, REMOTE_ADDR);
    }

    return 0;
}


static int extend_max_local_streams_bidi(ngtcp2_conn *conn,
                                         uint64_t max_streams,
                                         void *user_data) {
#ifdef MESSAGE
    struct client *c = user_data;
    int rv;
    int64_t stream_id;
    (void)max_streams;

    if (c->stream.stream_id != -1) {
        return 0;
    }

    // Open a new bidirectional stream
    rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
    if (rv != 0) {
        return 0;
    }

    c->stream.stream_id = stream_id;
    c->stream.data = (const uint8_t *)MESSAGE;
    c->stream.datalen = sizeof(MESSAGE) - 1;

    return 0;
#else  /* !defined(MESSAGE) */
    (void)conn;
    (void)max_streams;
    (void)user_data;

    return 0;
#endif /* !defined(MESSAGE) */
}


static void rand_cb(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
    int rv;
    (void)rand_ctx;

    rv = wolfSSL_RAND_bytes(dest, (int)destlen);
    if (rv != 1) {
        assert(0);
        abort();
    }
}

static int client_read(struct client *c) {
    uint8_t buf[4096];
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = sizeof(buf),
    };
    struct sockaddr_storage addr;
    struct msghdr msg = {0};
    ssize_t nread;
    ngtcp2_path path;
    ngtcp2_pkt_info pi = {0};
    int rv;

    msg.msg_name = &addr;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for(;;) {
        msg.msg_namelen = sizeof(addr);

        nread = recvmsg(c->fd, &msg, MSG_DONTWAIT);
        if(nread == -1) {
            if(errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "recvmsg failed : %s\n", strerror(errno));
            }
            break;
        }

        printf("nread is %d\n", nread);

        path.local.addr = (struct sockaddr*)&c->local_addr;
        path.local.addrlen = c->local_addrlen;

        path.remote.addr = msg.msg_name;
        path.remote.addrlen = msg.msg_namelen;

        rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)nread,
                                timestamp());
        if(rv != 0) {
            fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
            if (!c->last_error.error_code) {
                // Error at the TLS level
                if (rv == NGTCP2_ERR_CRYPTO) {
                    ngtcp2_ccerr_set_tls_alert(
                        &c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
                } else {
                    ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
                }
            }
            return -1;
        }
        printf("ngtcp2_conn_read_pkt returned %d\n", rv);
    }

    return 0;
}


static int client_send_packet(struct client *c, const uint8_t *data,
                              size_t datalen) {

    struct iovec iov = {
        .iov_base = (uint8_t *)data,
        .iov_len = datalen,
    };

    struct msghdr msg = {0};
    ssize_t nwrite;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    do {
        nwrite = sendmsg(c->fd, &msg, 0);
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite == -1) {
        fprintf(stderr, "sendmsg failed : %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static size_t client_get_message(struct client *c, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav) {

    if(c->stream.stream_id != -1 && c->stream.nwrite < c->stream.datalen) {
        *pstream_id = c->stream.stream_id;
        *pfin = 1;
        datav->base = (uint8_t *)c->stream.data + c->stream.nwrite;
        datav->len = c->stream.datalen - c->stream.nwrite;
        return 1;
    }

    *pstream_id = -1;
    *pfin = 0;
    datav->base = NULL;
    datav->len = 0;

    return 0;
}

static int client_write_streams(struct client *c) {
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite, wdatalen;
    ngtcp2_path_storage ps;
    ngtcp2_vec datav;
    uint8_t buf[1452]; // todo : why 1452?
    size_t datavcnt;
    int64_t stream_id;
    uint32_t flags;
    int fin;

    ngtcp2_path_storage_zero(&ps);

    for(;;) {
        // Get a message from the active stream of client
        // todo : It seems like a single stream is supported
        datavcnt = client_get_message(c, &stream_id, &fin, &datav);

        // More data might come and it should be coalesced in the same packet if possible.
        flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if(fin)
            // A passed data is the final part of a stream.
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        nwrite = ngtcp2_conn_writev_stream(c->conn, &ps.path, &pi, buf, sizeof(buf),
                                    &wdatalen, flags, stream_id, &datav,
                                    datavcnt, ts);
        if(nwrite == NGTCP2_ERR_WRITE_MORE) {
            // There is more data to be read
            c->stream.nwrite += (size_t)wdatalen;
            continue;
        } else if(nwrite < 0) {
            // TODO : We should call ngtcp2_conn_write_connection_close, but it
            // seems that it is called in client_close already, so we should be fine with this.
            fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
                    ngtcp2_strerror((int)nwrite));
            ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
            return -1;
        } else if(nwrite == 0) {
            return 0;
        }

        // todo : understand what wdatalen is
        if (wdatalen > 0) {
            c->stream.nwrite += (size_t)wdatalen;
        }

        if(client_send_packet(c, buf, (size_t)nwrite) != 0) {
            break;
        }
    }

    return 0;
}

static void client_close(struct client *c) {
    ngtcp2_ssize nwrite;
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    uint8_t buf[1280];

    if (ngtcp2_conn_in_closing_period(c->conn) ||
        ngtcp2_conn_in_draining_period(c->conn)) {
        goto fin;
    }

    ngtcp2_path_storage_zero(&ps);
    nwrite = ngtcp2_conn_write_connection_close(
        c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
    if (nwrite < 0) {
        fprintf(stderr, "ngtcp2_conn_write_connection_close failed: %s\n",
            ngtcp2_strerror((int)nwrite));
        goto fin;
    }

    client_send_packet(c, buf, (size_t)nwrite);

fin:
    uv_stop(uv_default_loop());
}

static int client_write(struct client *c) {
    // Uses nanoseconds
    ngtcp2_tstamp expiry, now;

    if (client_write_streams(c) != 0) {
        return -1;
    }

    expiry = ngtcp2_conn_get_expiry(c->conn);
    now = timestamp();

    // libuv takes milliseconds
    uint64_t t = expiry < now ? 1e-9 : (expiry - now) / 1000;

    uv_timer_set_repeat(&c->timer, t);
    int rv = uv_timer_again(&c->timer);
    printf("uv_timer_again returned %d and timeout is %ul\n", rv, t);

    return 0;
}

static void read_cb(uv_poll_t* handle, int status, int events) {
    struct client *c = handle->data;
    (void)status;
    (void)events;

    printf("read_cb was called!\n");
    if (client_read(c) != 0) {
        client_close(c);
        return;
    }

    if (client_write(c) != 0) {
        client_close(c);
    }
}

static int client_handle_expiry(struct client *c) {
    int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_handle_expiry failed: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    return 0;
}

static void timer_cb(uv_timer_t *handle) {
    struct client *c = handle->data;

    // Check if the connection expired due to inactivity
    if (client_handle_expiry(c) != 0) {
        client_close(c);
        return;
    }

    // Try to write
    if (client_write(c) != 0) {
        client_close(c);
    }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token,
                                    size_t cidlen, void *user_data) {
    (void)conn;
    (void)user_data;


    if(wolfSSL_RAND_bytes(cid->data, (int)cidlen) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    if(wolfSSL_RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int client_quic_init(struct client *c,
                            const struct sockaddr *remote_addr,
                            socklen_t remote_addrlen,
                            const struct sockaddr *local_addr,
                            socklen_t local_addrlen) {
    
    // Defines the network endpoints of the connection.
    ngtcp2_path path = {
        .local =
            {
                .addr = (struct sockaddr *)local_addr,
                .addrlen = local_addrlen,
            },
        .remote =
            {
                .addr = (struct sockaddr *)remote_addr,
                .addrlen = remote_addrlen,
            },
    };

    // Define various callbacks needed during a QUIC connection.
    ngtcp2_callbacks callbacks = {
        .client_initial = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_retry = ngtcp2_crypto_recv_retry_cb,
        .extend_max_local_streams_bidi = extend_max_local_streams_bidi,
        .rand = rand_cb,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        .get_new_connection_id = get_new_connection_id_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    };

    // Destination connection ID
    ngtcp2_cid dcid;
    // Source connection ID
    ngtcp2_cid scid;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    int rv;

    // Generate a random dcid
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    if (wolfSSL_RAND_bytes(dcid.data, (int)dcid.datalen) != 1) {
        fprintf(stderr, "wolfSSL_RAND_bytes failed\n");
        return -1;
    }

    // Generate a random scid
    scid.datalen = 8;
    if (wolfSSL_RAND_bytes(scid.data, (int)scid.datalen) != 1) {
        fprintf(stderr, "wolfSSL_RAND_bytes failed\n");
        return -1;
    }

    ngtcp2_settings_default(&settings);

    settings.initial_ts = timestamp();
    settings.log_printf = log_printf;

    ngtcp2_transport_params_default(&params);

    // The number of concurrent streams the client can create
    params.initial_max_streams_uni = 3;
    // The number of bytes that the client can transmit
    params.initial_max_stream_data_bidi_local = 128 * 1024;
    // The connection level flow control window
    params.initial_max_data = 1024 * 1024;

    rv =
    ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, //todo : is this proto version ok?
                           &callbacks, &settings, &params, NULL, c);
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_client_new failed: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);
    
    return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    struct client *c = conn_ref->user_data;
    return c->conn;
}

static int client_init(struct client *c) {
    struct sockaddr_storage remote_addr, local_addr;
    socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);

    memset(c, 0, sizeof(*c));

    // Reset the error
    ngtcp2_ccerr_default(&c->last_error);

    // Create a socket
    c->fd = create_sock((struct sockaddr *)&remote_addr, &remote_addrlen,
                          REMOTE_ADDR, REMOTE_PORT);
    if (c->fd == -1) {
        fprintf(stderr, "create_sock : %s\n", strerror(errno));
        return -1;
    }

    // Connect to the remote address
    if (connect_sock((struct sockaddr *)&local_addr, &local_addrlen, c->fd, 
                     (struct sockaddr *)&remote_addr, &remote_addrlen)) {
        fprintf(stderr, "connect_sock() failed.");
        return -1;
    }

    memcpy(&c->local_addr, &local_addr, sizeof(local_addr));
    c->local_addrlen = local_addrlen;

    // Initialize the SSL context and session
    if (client_ssl_init(c) != 0) {
        fprintf(stderr, "client_ssl_init() failed.\n");
        return -1;
    }

    if (client_quic_init(c, (struct sockaddr*)&remote_addr, remote_addrlen,
                            (struct sockaddr*)&local_addr, local_addrlen) != 0) {
        fprintf(stderr, "client_quic_init() failed.\n");
        return -1;
    }

    c->stream.stream_id = -1;

    c->conn_ref.get_conn = get_conn;
    c->conn_ref.user_data = c;

    // Initialize reader callback
    uv_poll_init(uv_default_loop(), &c->handle, c->fd);
    printf("Listening on port %d\n", c->fd);
    c->handle.data = c;
    uv_poll_start(&c->handle, UV_READABLE, read_cb);

    // Initialize timer that will:
    // - check if the connection expired
    // - write to the peer
    uv_timer_init(uv_default_loop(), &c->timer);
    c->timer.data = c;
    uv_timer_start(&c->timer, timer_cb, 0, 0);

    return 0;
}

static void client_free(struct client *c) {
    ngtcp2_conn_del(c->conn);
    wolfSSL_free(c->ssl);
    wolfSSL_CTX_free(c->ssl_ctx);
}

int main() {
    struct client c;

    // Set the seed for the random number generator
    srandom((unsigned int )timestamp());

    printf("client_init starting...\n");
    // SSL and QUIC client initialization
    if (client_init(&c) != 0) {
        fprintf(stderr, "client_init() failed\n");
        exit(EXIT_FAILURE);
    }
    printf("client_init done...\n");

    wolfSSL_Debugging_ON();
    wolfSSL_CTX_set_verify(c.ssl_ctx, WOLFSSL_VERIFY_NONE, verify_callback);

    // Send a message - establishes the handshake as well
    if (client_write(&c) != 0) {
        fprintf(stderr, "client_write() failed.\n");
        exit(EXIT_FAILURE);
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    client_free(&c);

    return 0;
}