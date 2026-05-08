/****************************************************************************
 * apps/netutils/ngtcp2/quic_server.c
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

#define LOCAL_PORT "8888"
#define ALPN "\x2h3"
#define RESPONSE "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!"

static const char server_cert_pem[] =
    "-----BEGIN CERTIFICATE-----"
    "MIIDijCCAnICCQDbemLFsbXeZDANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMC"
    "WFgxEjAQBgNVBAgMCVN0YXRlTmFtZTERMA8GA1UEBwwIQ2l0eU5hbWUxFDASBgNV"
    "BAoMC0NvbXBhbnlOYW1lMRswGQYDVQQLDBJDb21wYW55U2VjdGlvbk5hbWUxHTAb"
    "BgNVBAMMFENvbW1vbk5hbWVPckhvc3RuYW1lMB4XDTI2MDUwNzE3Mjg0NloXDTM2"
    "MDUwNDE3Mjg0NlowgYYxCzAJBgNVBAYTAlhYMRIwEAYDVQQIDAlTdGF0ZU5hbWUx"
    "ETAPBgNVBAcMCENpdHlOYW1lMRQwEgYDVQQKDAtDb21wYW55TmFtZTEbMBkGA1UE"
    "CwwSQ29tcGFueVNlY3Rpb25OYW1lMR0wGwYDVQQDDBRDb21tb25OYW1lT3JIb3N0"
    "bmFtZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKuxI9s1bc5RecEF"
    "vrxpnQADihjVQC+HHLUuzFPaUrhzfNtEIjMKXyHo4X+5vxSfRS+YZMZhQEJz8btV"
    "ZCCApDC64HjHW5/LUL6oS5uHqp6g8P2/uHVHTk2V7t0yMOLdJg5uMIUSDiiCBold"
    "R3AjfGM4iIgoW6SiYGeAGzUXudKXnu0Vm/uk/WUn6guX4m2vxJjygKKt/LNIMhgF"
    "PQYawI47mTkqxe5HZsu3u2xTpmFPb5XO7jVC6jLvzbTLGlR9JqYWVcY8QFbYirZT"
    "1RErhG/ZHgJYPKJ87TRn+Ka12dFWeUcO0fpp0tYY97P0s0ztpvZ2KD2kY1N93pV+"
    "jw8wm8ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAlLfsmwo+XweOJ0HZScmL+LSt"
    "/GHDEgpdK7Po5Sr1gLAd/n6vN2xD97F7KDbfBMd2EmJEWo8iqIWuwCHtqojjsyyT"
    "KhRl8VMdXWhBegWU0hq3/FEB45oK/XTclTVz2csd6inHPXp8Toi1NH04FS3CFbVy"
    "4qpl85S9sFvnpGM80Ln1WAcnAQsZHvKx2lqQyXKE2LT1YrkYXTepTpC8aAaDGENa"
    "Lt7r2FCXsoEaZDoy/Tk4nfRXhsujvzckCkJDIp76QhF3xhd4XkAeeVjRyXSQd+M2"
    "HifebnQ9aHnKzkl995rbbmrjbdBsxCcXC7jN07YzqsmYkk3IaGxOXpYo+N+rJw=="
    "-----END CERTIFICATE-----";

static const char server_key_pem[] =
    "-----BEGIN PRIVATE KEY-----"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrsSPbNW3OUXnB"
    "Bb68aZ0AA4oY1UAvhxy1LsxT2lK4c3zbRCIzCl8h6OF/ub8Un0UvmGTGYUBCc/G7"
    "VWQggKQwuuB4x1ufy1C+qEubh6qeoPD9v7h1R05Nle7dMjDi3SYObjCFEg4oggaJ"
    "XUdwI3xjOIiIKFukomBngBs1F7nSl57tFZv7pP1lJ+oLl+Jtr8SY8oCirfyzSDIY"
    "BT0GGsCOO5k5KsXuR2bLt7tsU6ZhT2+Vzu41Quoy7820yxpUfSamFlXGPEBW2Iq2"
    "U9URK4Rv2R4CWDyifO00Z/imtdnRVnlHDtH6adLWGPez9LNM7ab2dig9pGNTfd6V"
    "fo8PMJvBAgMBAAECggEAfPyWarUJe8GqTc793DFSPrlU5eEQOck1J9yqmHx97ZL9"
    "GK4P63IocQoUZqP0q3GKryxUaGpRmk7HciWmn1amsGbKlIIkfD5JSJJBgDaSCaqF"
    "5WOVR6MiKK72VYZ9Ohnd43Fp1uWe8vQ9B/Ck2cire5ujIOOoW0Btx8rlg5ADEX9n"
    "z2VQJq/lMedXQ5Vo9UKAEQht8J/FAUlEJCjtoIXPMZltFT+N8XAB3hD4hBM33+2/"
    "LAzPIrw7rRu7T4eV7pQ/bPA8l+11OtXR1ppceXWfvPe4s4bVSJumM/fAhjrKCjSK"
    "zIwKF9lbzn0Z25Ueo+g6fuDxqLLfyoZEhtI43MWa8QKBgQDR46c2nsogZjNJPWNx"
    "3DUGCaPeSabeeHx5iWICoG9Fklp8jw/7L5VkVgU+KH85dwkytbf14LNALdgPW4wm"
    "jjyMIYitBoSdoh5EUTivLAONmzzZ20VFp/YEjpyb5S5Mk9ZJRBRW93LWzW5piYgj"
    "Fha1PAoHuRN2tr2JPg+U1aEi/QKBgQDRaTzyUu7maKImB5FTRb5C485eY4klS9S4"
    "+TKrZlq1pu3UrYOQlvd9lEBWkkvWcH4k6ZkfmaOr1kt7/NHIARJuKD2oGqcAI+L4"
    "sInNbdnYzMo15OpcvsdIuFmLWm2YeJTFXrbQQ9issewTd1lmkHHkY1p/TWhUMVvM"
    "Wx2nc3jBFQKBgB3GTsVH12KrPOFJ7R6M35TAr1dsWVi7/OR84cN/oOlcrqt23AyF"
    "HotCTLIZqpqrUUm5T6R4wNT86+aZ1RLvIJW8eBgbkZqPEf4dC46GDub6u7IoEfak"
    "shjJZlwTMfM5EbAJEV2Y8tiYAe7EzOQ1UPla0A1yatlvaQncHPe/KoG9AoGBAI6z"
    "CwAKOZezB4OotoQrS3qjZ/Z0F3nd0ch2r+uSpQ+SABFkZ/n4lg/yHWGg8aLgJ2WZ"
    "9WlONfUb43ZLEt0atedw7osGFnUG/1z+V/kv+To+WzEcnAO1UXGhhgtrBLHYwXA5"
    "mZQUF6ue1sNxGe/FUIcUmQ+UvRpaRDbehDeefVP9AoGAL9qC6qvKWxa1ycps0u2o"
    "xL+eW8Ku0sEhcgc9S53DJO+gTvZ8796krTRJHstkHypO3wbkiRr1GKLo7kO4u9M1"
    "+B6Fzwpfla5A21SUZkD0EilhfcUy5Y/1VmER9ZUb5eEwDvdEn2/PHA9Av7iDcIuV"
    "myLH6ZgpqtoBTtb4FlDfpPQ="
    "-----END PRIVATE KEY-----";

struct server {
    ngtcp2_crypto_conn_ref conn_ref;
    int fd;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    WOLFSSL_CTX *ssl_ctx;
    SSL *ssl;
    ngtcp2_conn *conn;

    struct {
        int64_t stream_id;
        uint8_t buf[4096];
        size_t buflen;
        size_t nread;
        size_t nwrite;
    } stream;

    int handshake_complete;
    int stream_closed;

    ngtcp2_ccerr last_error;

    uv_poll_t handle;
    uv_timer_t timer;
};

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

static int create_sock(struct sockaddr_storage *local_addr, socklen_t *local_addrlen,
                       const char *port) {
    struct addrinfo hints = {0};
    struct addrinfo *res, *rp;
    int rv, fd = -1;

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    rv = getaddrinfo(NULL, port, &hints, &res);
    if (rv != 0) {
        fprintf(stderr, "getaddrinfo() returned %s\n", gai_strerror(rv));
        return -1;
    }

    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }

        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            *local_addrlen = rp->ai_addrlen;
            memcpy(local_addr, rp->ai_addr, rp->ai_addrlen);
            break;
        }

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int verify_callback(int mode, WOLFSSL_X509_STORE_CTX* ctx)
{
    (void)mode;
    (void)ctx;
    return 1;
}

static int server_ssl_ctx_init(struct server *s) {
    WOLFSSL_METHOD* method = TLS_server_method();
    if (!method) {
        fprintf(stderr, "could not get TLS server method\n");
        return -1;
    }

    s->ssl_ctx = wolfSSL_CTX_new(method);
    if (!s->ssl_ctx) {
        fprintf(stderr, "wolfSSL_CTX_new() failed.\n");
        return -1;
    }

    wolfSSL_CTX_set_verify(s->ssl_ctx, WOLFSSL_VERIFY_NONE, NULL);

    if (ngtcp2_crypto_wolfssl_configure_server_context(s->ssl_ctx) != 0) {
        fprintf(stderr, "ngtcp2_crypto_wolfssl_configure_server_context() failed\n");
        return -1;
    }

    int ret = wolfSSL_CTX_set_cipher_list(s->ssl_ctx,
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_set_cipher_list failed: %d\n", ret);
    }

    int groups[] = {
        WOLFSSL_ECC_X25519,
        WOLFSSL_ECC_SECP256R1,
        WOLFSSL_ECC_SECP384R1,
        WOLFSSL_ECC_SECP521R1,
    };
    ret = wolfSSL_CTX_set_groups(s->ssl_ctx, groups, (int)(sizeof(groups) / sizeof(groups[0])));
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_set_groups failed: %d\n", ret);
    }

    unsigned char alpn[] = {0x02, 'h', '3'};
    wolfSSL_CTX_set_alpn_protos(s->ssl_ctx, alpn, sizeof(alpn));

    if (wolfSSL_CTX_use_certificate_buffer(s->ssl_ctx,
            (const unsigned char *)server_cert_pem,
            sizeof(server_cert_pem),
            SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_use_certificate_buffer failed\n");
        return -1;
    }

    if (wolfSSL_CTX_use_PrivateKey_buffer(s->ssl_ctx,
            (const unsigned char *)server_key_pem,
            sizeof(server_key_pem),
            SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_use_PrivateKey_buffer failed\n");
        return -1;
    }

    return 0;
}

static int server_ssl_session_init(struct server *s) {
    s->ssl = wolfSSL_new(s->ssl_ctx);
    if (!s->ssl) {
        fprintf(stderr, "wolfSSL_new() failed.\n");
        return -1;
    }

    wolfSSL_set_app_data(s->ssl, &s->conn_ref);
    wolfSSL_set_accept_state(s->ssl);

    return 0;
}

static int server_recv_stream_data(ngtcp2_conn *conn,
                                    uint32_t flags,
                                    int64_t stream_id,
                                    uint64_t offset,
                                    const uint8_t *data,
                                    size_t datalen,
                                    void *user_data,
                                    void *stream_user_data) {
    struct server *s = user_data;
    (void)conn;
    (void)flags;
    (void)offset;
    (void)stream_user_data;

    if (s->stream.stream_id == -1) {
        s->stream.stream_id = stream_id;
    }

    if (s->stream.nread + datalen <= sizeof(s->stream.buf)) {
        memcpy(s->stream.buf + s->stream.nread, data, datalen);
        s->stream.nread += datalen;
    }

    printf("Server received %zu bytes on stream %" PRId64 "\n", datalen, stream_id);

    return 0;
}

static int server_stream_close(ngtcp2_conn *conn,
                                uint32_t flags,
                                int64_t stream_id,
                                uint64_t app_error_code,
                                void *user_data,
                                void *stream_user_data) {
    struct server *s = user_data;
    (void)conn;
    (void)stream_user_data;

    if (stream_id == s->stream.stream_id) {
        s->stream.buf[s->stream.nread] = '\0';
        printf("Stream %" PRId64 " closed. Received data: %s\n",
               stream_id, s->stream.buf);
        s->stream_closed = 1;
        
        memcpy(s->stream.buf, (const uint8_t *)RESPONSE, sizeof(RESPONSE) - 1);
        s->stream.buflen = sizeof(RESPONSE) - 1;
    }

    return 0;
}

static int server_extend_max_streams_bidi(ngtcp2_conn *conn,
                                           uint64_t max_streams,
                                           void *user_data) {
    (void)conn;
    (void)max_streams;
    (void)user_data;
    return 0;
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

static int server_read(struct server *s) {
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

    for (;;) {
        msg.msg_namelen = sizeof(addr);

        nread = recvmsg(s->fd, &msg, MSG_DONTWAIT);
        if (nread == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                fprintf(stderr, "recvmsg failed: %s\n", strerror(errno));
            }
            break;
        }

        if (s->remote_addrlen == 0) {
            s->remote_addrlen = msg.msg_namelen;
            memcpy(&s->remote_addr, msg.msg_name, msg.msg_namelen);
        }

        printf("Server read %zd bytes\n", nread);

        path.local.addr = (struct sockaddr*)&s->local_addr;
        path.local.addrlen = s->local_addrlen;

        path.remote.addr = msg.msg_name;
        path.remote.addrlen = msg.msg_namelen;

        rv = ngtcp2_conn_read_pkt(s->conn, &path, &pi, buf, (size_t)nread,
                                timestamp());
        if (rv != 0) {
            fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
            if (!s->last_error.error_code) {
                if (rv == NGTCP2_ERR_CRYPTO) {
                    ngtcp2_ccerr_set_tls_alert(
                        &s->last_error, ngtcp2_conn_get_tls_alert(s->conn), NULL, 0);
                } else {
                    ngtcp2_ccerr_set_liberr(&s->last_error, rv, NULL, 0);
                }
            }
            return -1;
        }
    }

    return 0;
}

static int server_send_packet(struct server *s, const uint8_t *data,
                              size_t datalen) {
    struct iovec iov = {
        .iov_base = (uint8_t *)data,
        .iov_len = datalen,
    };

    struct msghdr msg = {0};
    ssize_t nwrite;

    msg.msg_name = &s->remote_addr;
    msg.msg_namelen = s->remote_addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    do {
        nwrite = sendmsg(s->fd, &msg, 0);
    } while (nwrite == -1 && errno == EINTR);

    if (nwrite == -1) {
        fprintf(stderr, "sendmsg failed: %s\n", strerror(errno));
        return -1;
    }

    printf("Server sent %zd bytes\n", nwrite);
    return 0;
}

static size_t server_get_message(struct server *s, int64_t *pstream_id,
                                 int *pfin, ngtcp2_vec *datav) {
    if (s->stream_closed && s->stream.nwrite < s->stream.buflen) {
        *pstream_id = s->stream.stream_id;
        *pfin = 1;
        datav->base = (uint8_t *)s->stream.buf + s->stream.nwrite;
        datav->len = s->stream.buflen - s->stream.nwrite;
        return 1;
    }

    *pstream_id = -1;
    *pfin = 0;
    datav->base = NULL;
    datav->len = 0;

    return 0;
}

static int server_write_streams(struct server *s) {
    ngtcp2_tstamp ts = timestamp();
    ngtcp2_pkt_info pi;
    ngtcp2_ssize nwrite, wdatalen;
    ngtcp2_path_storage ps;
    ngtcp2_vec datav;
    uint8_t buf[1452];
    size_t datavcnt;
    int64_t stream_id;
    uint32_t flags;
    int fin;

    ngtcp2_path_storage_zero(&ps);

    for (;;) {
        datavcnt = server_get_message(s, &stream_id, &fin, &datav);

        flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if (fin)
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        nwrite = ngtcp2_conn_writev_stream(s->conn, &ps.path, &pi, buf, sizeof(buf),
                                    &wdatalen, flags, stream_id, &datav,
                                    datavcnt, ts);
        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
            s->stream.nwrite += (size_t)wdatalen;
            continue;
        } else if (nwrite < 0) {
            fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n",
                    ngtcp2_strerror((int)nwrite));
            ngtcp2_ccerr_set_liberr(&s->last_error, (int)nwrite, NULL, 0);
            return -1;
        } else if (nwrite == 0) {
            return 0;
        }

        if (wdatalen > 0) {
            s->stream.nwrite += (size_t)wdatalen;
        }

        if (server_send_packet(s, buf, (size_t)nwrite) != 0) {
            break;
        }
    }

    return 0;
}

static void server_close(struct server *s) {
    ngtcp2_ssize nwrite;
    ngtcp2_pkt_info pi;
    ngtcp2_path_storage ps;
    uint8_t buf[1280];

    if (ngtcp2_conn_in_closing_period(s->conn) ||
        ngtcp2_conn_in_draining_period(s->conn)) {
        goto fin;
    }

    ngtcp2_path_storage_zero(&ps);
    nwrite = ngtcp2_conn_write_connection_close(
        s->conn, &ps.path, &pi, buf, sizeof(buf), &s->last_error, timestamp());
    if (nwrite < 0) {
        fprintf(stderr, "ngtcp2_conn_write_connection_close failed: %s\n",
            ngtcp2_strerror((int)nwrite));
        goto fin;
    }

    server_send_packet(s, buf, (size_t)nwrite);

fin:
    uv_stop(uv_default_loop());
}

static int server_write(struct server *s) {
    ngtcp2_tstamp expiry, now;

    if (server_write_streams(s) != 0) {
        return -1;
    }

    expiry = ngtcp2_conn_get_expiry(s->conn);
    now = timestamp();

    uint64_t t = expiry < now ? 1e-9 : (expiry - now) / 1000;

    uv_timer_set_repeat(&s->timer, t);
    int rv = uv_timer_again(&s->timer);
    printf("uv_timer_again returned %d and timeout is %lu\n", rv, t);

    return 0;
}

static void read_cb(uv_poll_t* handle, int status, int events) {
    struct server *s = handle->data;
    (void)status;
    (void)events;

    printf("server read_cb was called!\n");
    if (server_read(s) != 0) {
        server_close(s);
        return;
    }

    if (server_write(s) != 0) {
        server_close(s);
    }
}

static int server_handle_expiry(struct server *s) {
    int rv = ngtcp2_conn_handle_expiry(s->conn, timestamp());
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_handle_expiry failed: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    return 0;
}

static void timer_cb(uv_timer_t *handle) {
    struct server *s = handle->data;

    if (server_handle_expiry(s) != 0) {
        server_close(s);
        return;
    }

    if (server_write(s) != 0) {
        server_close(s);
    }
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token,
                                    size_t cidlen, void *user_data) {
    (void)conn;
    (void)user_data;

    if (wolfSSL_RAND_bytes(cid->data, (int)cidlen) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    cid->datalen = cidlen;

    if (wolfSSL_RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
}

static int server_quic_init(struct server *s,
                            const struct sockaddr *remote_addr,
                            socklen_t remote_addrlen,
                            const struct sockaddr *local_addr,
                            socklen_t local_addrlen,
                            const ngtcp2_cid *dcid,
                            const ngtcp2_cid *scid) {
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

    ngtcp2_callbacks callbacks = {
        .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
        .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
        .encrypt = ngtcp2_crypto_encrypt_cb,
        .decrypt = ngtcp2_crypto_decrypt_cb,
        .hp_mask = ngtcp2_crypto_hp_mask_cb,
        .recv_stream_data = server_recv_stream_data,
        .stream_close = server_stream_close,
        .extend_max_local_streams_bidi = server_extend_max_streams_bidi,
        .rand = rand_cb,
        .update_key = ngtcp2_crypto_update_key_cb,
        .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
        .get_new_connection_id = get_new_connection_id_cb,
        .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
    };

    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    int rv;

    ngtcp2_settings_default(&settings);

    settings.initial_ts = timestamp();
    settings.log_printf = log_printf;

    ngtcp2_transport_params_default(&params);

    params.initial_max_streams_uni = 3;
    params.initial_max_streams_bidi = 3;
    params.initial_max_stream_data_bidi_local = 128 * 1024;
    params.initial_max_stream_data_bidi_remote = 128 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.original_dcid_present = 1;
    params.original_dcid = *dcid;
    
    rv = ngtcp2_conn_server_new(&s->conn, scid, dcid, &path, NGTCP2_PROTO_VER_V1,
                               &callbacks, &settings, &params, NULL, s);
    if (rv != 0) {
        fprintf(stderr, "ngtcp2_conn_server_new failed: %s\n", ngtcp2_strerror(rv));
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(s->conn, s->ssl);

    return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    struct server *s = conn_ref->user_data;
    return s->conn;
}

static int server_init(struct server *s) {
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen = sizeof(local_addr);

    memset(s, 0, sizeof(*s));

    ngtcp2_ccerr_default(&s->last_error);

    s->fd = create_sock(&local_addr, &local_addrlen, LOCAL_PORT);
    if (s->fd == -1) {
        fprintf(stderr, "create_sock failed: %s\n", strerror(errno));
        return -1;
    }

    memcpy(&s->local_addr, &local_addr, sizeof(local_addr));
    s->local_addrlen = local_addrlen;

    printf("Server listening on port %s\n", LOCAL_PORT);

    if (server_ssl_ctx_init(s) != 0) {
        fprintf(stderr, "server_ssl_ctx_init() failed.\n");
        return -1;
    }

    s->stream.stream_id = -1;
    s->stream.nread = 0;
    s->stream.nwrite = 0;
    s->stream_closed = 0;

    s->conn_ref.get_conn = get_conn;
    s->conn_ref.user_data = s;

    uv_poll_init(uv_default_loop(), &s->handle, s->fd);
    s->handle.data = s;
    uv_poll_start(&s->handle, UV_READABLE, read_cb);

    uv_timer_init(uv_default_loop(), &s->timer);
    s->timer.data = s;
    uv_timer_start(&s->timer, timer_cb, 0, 0);

    return 0;
}

static void server_free(struct server *s) {
    if (s->conn) {
        ngtcp2_conn_del(s->conn);
    }
    if (s->ssl) {
        wolfSSL_free(s->ssl);
    }
    if (s->ssl_ctx) {
        wolfSSL_CTX_free(s->ssl_ctx);
    }
    if (s->fd >= 0) {
        close(s->fd);
    }
}

static int decode_transport_params_new(ngtcp2_conn *conn,
                                        ngtcp2_cid *dcid,
                                        ngtcp2_cid *scid,
                                        const uint8_t *pkt,
                                        size_t pktlen) {
    ngtcp2_ssize rv;
    ngtcp2_pkt_hd hd;

    rv = ngtcp2_pkt_decode_hd_long(&hd, pkt, pktlen);
    if (rv < 0) {
        rv = ngtcp2_pkt_decode_hd_short(&hd, pkt, pktlen, 0);
        if (rv < 0) {
            return -1;
        }
    }

    *dcid = hd.dcid;
    *scid = hd.scid;

    return 0;
}

int main() {
    
    struct server s;
    uint8_t buf[4096];
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    ssize_t nread;
    ngtcp2_cid dcid, scid;

    srandom((unsigned int)timestamp());

    wolfSSL_Debugging_ON();

    if (server_init(&s) != 0) {
        fprintf(stderr, "server_init failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Waiting for client Initial packet...\n");

    ngtcp2_pkt_info pi = {0};
    ngtcp2_path path = {
        .local = {
            .addr = (struct sockaddr*)&s.local_addr,
            .addrlen = s.local_addrlen,
        },
    };

    for (;;) {
        struct msghdr msg = {0};
        struct iovec iov = {
            .iov_base = buf,
            .iov_len = sizeof(buf),
        };
        struct sockaddr_storage addr;

        msg.msg_name = &addr;
        msg.msg_namelen = sizeof(addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        nread = recvmsg(s.fd, &msg, 0);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            fprintf(stderr, "recvmsg failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        printf("Received initial packet of %zd bytes\n", nread);

        remote_addrlen = msg.msg_namelen;
        memcpy(&remote_addr, msg.msg_name, remote_addrlen);

        s.remote_addrlen = remote_addrlen;
        memcpy(&s.remote_addr, &remote_addr, remote_addrlen);

        if (decode_transport_params_new(s.conn, &dcid, &scid, buf, (size_t)nread) != 0) {
            fprintf(stderr, "Failed to decode transport parameters from Initial\n");
            exit(EXIT_FAILURE);
        }

        if (server_ssl_session_init(&s) != 0) {
            fprintf(stderr, "Failed to init SSL session for connection\n");
            exit(EXIT_FAILURE);
        }

        if (server_quic_init(&s,
                             (struct sockaddr*)&remote_addr, remote_addrlen,
                             (struct sockaddr*)&s.local_addr, s.local_addrlen,
                             &dcid, &scid) != 0) {
            fprintf(stderr, "server_quic_init failed\n");
            exit(EXIT_FAILURE);
        }

        s.conn_ref.get_conn = get_conn;
        s.conn_ref.user_data = &s;

        path.remote.addr = (struct sockaddr*)&remote_addr;
        path.remote.addrlen = remote_addrlen;

        int rv = ngtcp2_conn_read_pkt(s.conn, &path, &pi, buf, (size_t)nread,
                                     timestamp());
        if (rv != 0) {
            fprintf(stderr, "ngtcp2_conn_read_pkt (initial): %s\n", ngtcp2_strerror(rv));
            exit(EXIT_FAILURE);
        }

        break;
    }

    printf("Processing handshake...\n");

    if (server_write(&s) != 0) {
        fprintf(stderr, "server_write() failed after initial packet.\n");
        exit(EXIT_FAILURE);
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    server_free(&s);

    return 0;
}
