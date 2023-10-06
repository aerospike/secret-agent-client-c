/*
 * Copyright 2008-2022 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#include "sc_socket.h"
#include "sc_logging.h"

#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <pthread.h>


//==========================================================
// Typedefs & constants.
//

//==========================================================
// Globals.
//

pthread_mutex_t SC_TLS_INIT_MUTEX = PTHREAD_MUTEX_INITIALIZER;
bool SC_TLS_INITIALIZED = false;

//==========================================================
// Forward declarations.
//

static SSL_CTX* create_context();
static bool tls_load_ca_str(SSL_CTX* ctx, const char* cert_str);

//==========================================================
// Public API.
//

void
init_openssl()
{
	if (SC_TLS_INITIALIZED) {
		return;
	}

	pthread_mutex_lock(&SC_TLS_INIT_MUTEX);
	if (!SC_TLS_INITIALIZED) {
		SSL_load_error_strings();
		SSL_library_init();
		SC_TLS_INITIALIZED = true;
	}
	pthread_mutex_unlock(&SC_TLS_INIT_MUTEX);
}

// return of < 0 == failure
int
wrap_socket(sc_socket* sock)
{
    SSL_CTX* ctx = create_context();
	if (ctx == NULL) {
		return -1;
	}

	const char* ca_string = sock->tls_cfg->ca_string;
	if (ca_string && !tls_load_ca_str(ctx, ca_string)) {
		sc_g_log_function("ERR: unable to load ca certificate from ca_string");
		return -1;
	}

    SSL* ssl = SSL_new(ctx);
    if (ssl == NULL) {
        sc_g_log_function("ERR: unable to create new SSL context");
		return -1;
    }

    if (!SSL_set_fd(ssl, sock->fd)) {
		SSL_free(ssl);
		sc_g_log_function("ERR: unable to set SSL fd");
		return -1;
	}

    sock->ssl = ssl;
	return 0;
}

// return of < 0 == failure
int
tls_connect(sc_socket* sock, int timeout_ms)
{
	int rv;

	while (true) {
		rv = SSL_connect(sock->ssl);
		if (rv == 1) {
			// TODO log_session_info(sock);
			sc_g_log_function("INF: ssl connection succeeded");
			return 0;
		}

		int sslerr = SSL_get_error(sock->ssl, rv);
		short pollres = 0;
		unsigned long errcode;
		char errbuf[1024];
		switch (sslerr) {
		case SSL_ERROR_WANT_READ:
			rv = socket_wait(sock, timeout_ms, true, &pollres);
			if (rv <= 0) {
				sc_g_log_function("ERR: socket poll failed on tls connect, return value: %d, revent: %d, errno: %d", rv, pollres, errno);
				return rv;
			}
			// loop back around and retry
			break;
		case SSL_ERROR_WANT_WRITE:
			rv = socket_wait(sock, timeout_ms, false, &pollres);
			if (rv <= 0) {
				sc_g_log_function("ERR: socket poll failed on tls connect, return value: %d, revent: %d, errno: %d", rv, pollres, errno);
				return rv;
			}
			// loop back around and retry
			break;
		case SSL_ERROR_SSL:
			// TODO log_verify_details(sock);
			errcode = ERR_get_error();
			ERR_error_string_n(errcode, errbuf, sizeof(errbuf));
			sc_g_log_function("ERR: SSL_connect failed: %s", errbuf);
			return -1;
		case SSL_ERROR_SYSCALL:
			errcode = ERR_get_error();
			if (errcode != 0) {
				ERR_error_string_n(errcode, errbuf, sizeof(errbuf));
				sc_g_log_function("ERR: SSL_connect I/O error: %s", errbuf);
			}
			else {
				if (rv == 0) {
					sc_g_log_function("ERR: SSL_connect I/O error: unexpected EOF");
				}
				else {
					sc_g_log_function("ERR: SSL_connect I/O error: %d", errno);
				}
			}
			return -2;
		default:
			sc_g_log_function("ERR: SSL_connect: unexpected ssl error: %d", sslerr);
			return -3;
			break;
		}
	}
}

// return of < 0 == failure
int
tls_read_n_bytes(sc_socket* sock, void* buf, size_t len, int timeout_ms)
{
    size_t bytes_read = 0;

    while (true) {
        int rv = SSL_read(sock->ssl, buf + bytes_read, (int)(len - bytes_read));
		if (rv > 0) {
			bytes_read += rv;
			if (bytes_read >= len) {
				return bytes_read;
			}
		}
		else {
            int sslerr = SSL_get_error(sock->ssl, rv);
            short pollres = 0;
			unsigned long errcode;
			char errbuf[1024];
			switch (sslerr) {
			case SSL_ERROR_WANT_READ:
				rv = socket_wait(sock, timeout_ms, true, &pollres);
				if (rv <= 0) {
                    sc_g_log_function("ERR: socket poll failed on tls read, return value: %d, revent: %d, errno: %d", rv, pollres, errno);
					return rv;
				}
				// loop back around and retry
				break;
			case SSL_ERROR_WANT_WRITE:
				rv = socket_wait(sock, timeout_ms, false, &pollres);
				if (rv <= 0) {
                    sc_g_log_function("ERR: socket poll failed on tls read, return value: %d, revent: %d, errno: %d", rv, pollres, errno);
					return rv;
				}
				// loop back around and retry
				break;
			case SSL_ERROR_SSL:
				// TODO log_verify_details(sock);
				errcode = ERR_get_error();
				ERR_error_string_n(errcode, errbuf, sizeof(errbuf));
				sc_g_log_function("ERR: SSL_read failed: %s", errbuf);
				return -1;
			case SSL_ERROR_SYSCALL:
				errcode = ERR_get_error();
				if (errcode != 0) {
					ERR_error_string_n(errcode, errbuf, sizeof(errbuf));
					sc_g_log_function("ERR: SSL_read I/O error: %s", errbuf);
				}
				else {
					if (rv == 0) {
						sc_g_log_function("ERR: SSL_read I/O error: unexpected EOF");
					}
					else {
						sc_g_log_function("ERR: SSL_read I/O error: %d", errno);
					}
				}
				return -1;
			default:
				sc_g_log_function("ERR: SSL_read: unexpected ssl error: %d", sslerr);
				return -1;
				break;
			}
        }
    }
}

// return of < 0 == failure
int
tls_write(sc_socket* sock, void* bufp, size_t len, int timeout_ms)
{
	uint8_t* buf = (uint8_t *) bufp;
	size_t pos = 0;

	while (true) {
		int rv = SSL_write(sock->ssl, buf + pos, (int)(len - pos));
		if (rv > 0) {
			pos += rv;
			if (pos >= len) {
				return pos;
			}
		}
		else {
			int sslerr = SSL_get_error(sock->ssl, rv);
			short pollres = 0;
			unsigned long errcode;
			char errbuf[1024];
			switch (sslerr) {
			case SSL_ERROR_WANT_READ:
				rv = socket_wait(sock, timeout_ms, true, &pollres);
				if (rv <= 0) {
					sc_g_log_function("ERR: socket poll failed on tls write, return value: %d, revent: %d, errno: %d", rv, pollres, errno);
					return rv;
				}
				// loop back around and retry
				break;
			case SSL_ERROR_WANT_WRITE:
				rv = socket_wait(sock, timeout_ms, false, &pollres);
				if (rv <= 0) {
					sc_g_log_function("ERR: socket poll failed on tls write, return value: %d, revent: %d, errno: %d", rv, pollres, errno);
					return rv;
				}
				// loop back around and retry
				break;
			case SSL_ERROR_SSL:
				// TODO log_verify_details(sock);
				errcode = ERR_get_error();
				ERR_error_string_n(errcode, errbuf, sizeof(errbuf));
				sc_g_log_function("ERR: SSL_write failed: %s", errbuf);
				return -1;
			case SSL_ERROR_SYSCALL:
				errcode = ERR_get_error();
				if (errcode != 0) {
					ERR_error_string_n(errcode, errbuf, sizeof(errbuf));
					sc_g_log_function("ERR: SSL_write I/O error: %s", errbuf);
				}
				else {
					if (rv == 0) {
						sc_g_log_function("ERR: SSL_write I/O error: unexpected EOF");
					}
					else {
						sc_g_log_function("ERR: SSL_write I/O error: %d", errno);
					}
				}
				return -1;
			default:
				sc_g_log_function("ERR: SSL_write: unexpected ssl error: %d", sslerr);
				return -1;
				break;
			}
		}
	}
}

//==========================================================
// Local helpers.
//

static SSL_CTX*
create_context()
{
    const SSL_METHOD* method;
    SSL_CTX *ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        sc_g_log_function("unable to create SSL context");
    }

    return ctx;
}

static bool
tls_load_ca_str(SSL_CTX* ctx, const char* cert_str)
{
	BIO* cert_bio = BIO_new_mem_buf(cert_str, -1);

	if (cert_bio == NULL) {
		return false;
	}

	X509* cert;
	int count = 0;

	while ((cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL)) != NULL) {
		X509_STORE* store = SSL_CTX_get_cert_store(ctx);
		int rv = X509_STORE_add_cert(store, cert);

		if (rv == 1) {
			count++;
		}
		else {
			sc_g_log_function("ERR: failed to add TLS certificate from string");
		}

		X509_free(cert);
	}

	// Above loop always ends with an error - clear it so it doesn't affect
	// subsequent SSL calls in this thread.
	ERR_clear_error();
	BIO_vfree(cert_bio);

	if (count == 0) {
		return false;
	}
	return true;
}