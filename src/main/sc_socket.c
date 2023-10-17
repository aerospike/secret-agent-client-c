/*
 * Copyright 2008-2023 Aerospike, Inc.
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

//==========================================================
// Includes.
//

#include "sc_error.h"
#include "sc_socket.h"
#include "sc_tls.h"
#include "sc_logging.h"

#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <netdb.h>

//==========================================================
// Typedefs & constants.
//

#define SC_MAX_PORT 65535
#define SC_MIN_PORT 1

//==========================================================
// Forward Declarations.
//

static sc_socket* sc_socket_init(sc_socket* sock);
static sc_err _read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);
static sc_err _write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);
static int lookup_host(const char* hostname, const char* port, struct addrinfo** res);

//==========================================================
// Public API.
//

// This assumes buffer is at least n bytes long.
sc_err
sc_read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
	if (sock->tls_cfg->enabled) {
		return sc_tls_read_n_bytes(sock, n, buffer, timeout_ms);
	}
	else {
		return _read_n_bytes(sock, n, buffer, timeout_ms);
	}
}

// This assumes buffer is at least n bytes long.
sc_err
sc_write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
	if (sock->tls_cfg->enabled) {
		return sc_tls_write_n_bytes(sock, n, buffer, timeout_ms);
	}
	else {
		return _write_n_bytes(sock, n, buffer, timeout_ms);
	}
}

sc_err 
sc_connect_addr_port(sc_socket** sockp, const char* addr, const char* port, sc_tls_cfg* tls_cfg, int timeout_ms)
{
	sc_err err;
	err.code = SC_OK;

	long port_num = strtol(port, NULL, 10);
	if (port_num < SC_MIN_PORT || port_num > SC_MAX_PORT) {
		sc_g_log_function("ERR: port: %ld is outside the valid port range %d - %d", port_num, SC_MIN_PORT, SC_MAX_PORT);
		err.code = SC_FAILED_BAD_CONFIG;
		return err;
	}

	struct addrinfo *host_info, *p;
	int lookup_res = lookup_host(addr, port, &host_info);
	if (lookup_res != 0) {
		sc_g_log_function("ERR: failed to lookup address: %s", addr);
		err.code = SC_FAILED_BAD_CONFIG;
		return err;
	}

	int sock_fd;
	// loop through all the results and connect to the first we can
	for(p = host_info; p != NULL; p = p->ai_next) {
		if ((sock_fd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			continue;
		}

		if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sock_fd);
			continue;
		}

		break; // successfully connected
	}

	if (p == NULL) {
		// looped off the end of the list with no connection
		sc_g_log_function("ERR: connect failed: %d, errno: %d", sock_fd, errno);
		err.code = SC_FAILED_INTERNAL;
		freeaddrinfo(host_info);
		return err;
	}

	freeaddrinfo(host_info);

	// mark the socket as non-blocking
	int fcntl_res = fcntl(sock_fd, F_SETFL, O_NONBLOCK);
	if (fcntl_res < 0) {
		sc_g_log_function("ERR: could not set socket to non-blocking: %d", fcntl_res);
		err.code = SC_FAILED_INTERNAL;
		return err;
	}

	// wrap the socket, must be freed by caller
	sc_socket* sock = (sc_socket*) malloc(sizeof(sc_socket));
	if (sock == NULL) {
		sc_g_log_function("ERR: could not allocate memory for sc_socket");
		err.code = SC_FAILED_INTERNAL;
		return err;
	}

	sock = sc_socket_init(sock);
	sock->fd = sock_fd;

	sock->tls_cfg = tls_cfg;
	if (tls_cfg->enabled) {
		sc_init_openssl();
		if (sc_wrap_socket(sock) < 0) {
			sc_g_log_function("ERR: failed to wrap socket for tls");
			err.code = SC_FAILED_INTERNAL;

			close(sock_fd);
			free(sock);

			return err;
		}

		err = sc_tls_connect(sock, timeout_ms);

		if (err.code != SC_OK) {
			sc_g_log_function("ERR: tls connection failed: %d", err.code);
			close(sock_fd);
			sc_socket_destroy(sock);
			return err;
		}
	}

	*sockp = sock;
	return err; 
}

sc_err
sc_socket_wait(sc_socket* sock, int timeout_ms, bool read, short* poll_res)
{
	sc_err err;
	err.code = SC_OK;

	short events = POLLOUT;

	if (read) {
		events = POLLIN;
	}

	struct pollfd pfd = {
		.fd = sock->fd,
		.events = events
	};

	nfds_t fd_count = 1;
	int p_res = poll(&pfd, fd_count, (int)timeout_ms);

	if (p_res == 0) {
		sc_g_log_function("ERR: socket poll timed out");
		err.code = SC_FAILED_TIMEOUT;
		return err;
	}
	else if (p_res < 0) {
		sc_g_log_function("ERR: socket poll err: %d, errno: %d", p_res, errno);
		err.code = SC_FAILED_INTERNAL;
		return err;
	}

	*poll_res = pfd.revents;

	int socket_ready = 0;
	if (read) {
		socket_ready = *poll_res & POLLIN;
	}
	else {
		socket_ready = *poll_res & POLLOUT;
	}

	if (!socket_ready) {
		sc_g_log_function("ERR: no sockets ready, revent: %d", pfd.revents);
		err.code = SC_FAILED_INTERNAL;
		return err;
	}

	return err;
}

sc_tls_cfg*
sc_tls_cfg_init(sc_tls_cfg* cfg)
{
	cfg->ca_string = NULL;
	cfg->enabled = false;
	return cfg;
}

sc_tls_cfg*
sc_tls_cfg_new()
{
	sc_tls_cfg* cfg = (sc_tls_cfg*) malloc(sizeof(sc_tls_cfg));
	sc_tls_cfg_init(cfg);
	return cfg;
}

void
sc_socket_destroy(sc_socket* sock)
{
	if (sock->ssl != NULL) {
		SSL_free(sock->ssl);
	}

	free(sock);
}

//==========================================================
// Private Helpers.
//

sc_socket*
sc_socket_init(sc_socket* sock)
{
	sock->fd = -2; // -2 so we can distinguish from -1 error and valid FDs
	sock->ssl = NULL;
	sock->tls_cfg = NULL;

	return sock;
}

sc_err
_read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
	sc_err err;
	err.code = SC_OK;

	int total_bytes_read = 0;
	short poll_res = 0;
	while (true)
	{
		err = sc_socket_wait(sock, timeout_ms, true, &poll_res);
		if (err.code != SC_OK) {
			sc_g_log_function("ERR: socket poll failed on read, return value: %d, revent: %d, errno: %d", err.code, poll_res, errno);
			return err;
		}

		int bytes_read = read(sock->fd, buffer + total_bytes_read, n - total_bytes_read);
		if (bytes_read < 0 ) {
			sc_g_log_function("ERR: socket read failed, return value: %d, errno: %d", bytes_read, errno);
			err.code = SC_FAILED_INTERNAL;
			return err;
		}

		if (bytes_read == 0) {
			// end of transmission
			return err;
		}

		total_bytes_read += bytes_read;
		if (total_bytes_read >= n) {
			return err;
		}
	}
}

sc_err
_write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
	sc_err err;
	err.code = SC_OK;

	int total_bytes_written = 0;
	short poll_res = 0;
	while (true)
	{
		err = sc_socket_wait(sock, timeout_ms, false, &poll_res);
		if (err.code != SC_OK) {
			err.code = SC_FAILED_INTERNAL;
			sc_g_log_function("ERR: socket poll failed on write, return value: %d, revent: %d, errno: %d", err.code, poll_res, errno);
			return err;
		}

		int bytes_written = write(sock->fd, buffer + total_bytes_written, n - total_bytes_written);
		if (bytes_written < 0 )
		{
			sc_g_log_function("ERR: socket write failed, return value: %d, errno: %d", bytes_written, errno);
			err.code = SC_FAILED_INTERNAL;
			return err;
		}

		total_bytes_written += bytes_written;
		if (total_bytes_written >= n) {
			return err;
		}
	}
}

/*
 * lookup_host points res to a heap allocated
 * addrinfo struct containing host information for
 * host at hostname and port
 * SUCCESS: 0 is returned.
 * FAILURE: A value other than 0 is returned.
*/
int
lookup_host(const char* hostname, const char* port, struct addrinfo** res)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Check if hostname is really an IPv4 address.
	struct in_addr ipv4;

	if (inet_pton(AF_INET, hostname, &ipv4) == 1) {
		hints.ai_family = AF_INET;
		hints.ai_flags = AI_NUMERICHOST;
	}
	else {
		// Check if hostname is really an IPv6 address.
		struct in6_addr ipv6;
		
		if (inet_pton(AF_INET6, hostname, &ipv6) == 1) {
			hints.ai_family = AF_INET6;
			hints.ai_flags = AI_NUMERICHOST;
		}
	}

	int ret = getaddrinfo(hostname, port, &hints, res);
	return ret;
}