/*
 * secrets.c
 *
 * Copyright (C) 2023 Aerospike, Inc.
 *
 * All rights reserved.
 *
 * THIS IS UNPUBLISHED PROPRIETARY SOURCE CODE. THE COPYRIGHT NOTICE ABOVE DOES
 * NOT EVIDENCE ANY ACTUAL OR INTENDED PUBLICATION.
 */

//==========================================================
// Includes.
//

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
// Forward Declarations.
//

int _read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);
int _write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms);
int lookup_host(const char* hostname, const char* port, struct addrinfo** res);

//==========================================================
// Public API.
//

int read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
    if (sock->tls_cfg->enabled) {
        return tls_read_n_bytes(sock, buffer, n, timeout_ms);
    }
    else {
        return _read_n_bytes(sock, n, buffer, timeout_ms);
    }
}

// This assumes buffer is at least n bytes long
int write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
    if (sock->tls_cfg->enabled) {
        return tls_write(sock, buffer, n, timeout_ms);
    }
    else {
        int res = _write_n_bytes(sock, n, buffer, timeout_ms);
        if (res == 0) {
            return -1;
        }
        return res;
    }
}

sc_socket* 
connect_addr_port(const char* addr, const char* port, sc_tls_cfg* tls_cfg, int timeout_ms)
{

    long port_num = strtol(port, NULL, 10);
    if (port_num < 1 || port_num > 65535) {
		sc_g_log_function("ERR: port: %ld is outside the valid port range 1 - 65535", port_num);
		return NULL;
    }

    struct addrinfo *host_info, *p;
    int lookup_res = lookup_host(addr, port, &host_info);
    if (lookup_res != 0) {
		sc_g_log_function("ERR: failed to lookup address: %s");
		return NULL;
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
        freeaddrinfo(host_info);
        return NULL;
    }

    freeaddrinfo(host_info);

    // mark the socket as non-blocking
    int fcntl_res = fcntl(sock_fd, F_SETFL, O_NONBLOCK);
    if (fcntl_res < 0) {
        sc_g_log_function("ERR: could not set socket to non-blocking: %d", fcntl_res);
        return NULL;
    }

    // wrap the socket, must be freed by caller
    sc_socket* sock = (sc_socket*) malloc(sizeof(sc_socket));
    sock->fd = sock_fd;

    sock->tls_cfg = tls_cfg;
    if (tls_cfg->enabled) {
        init_openssl();
        wrap_socket(sock);
        int connect_res = tls_connect(sock, timeout_ms);

        if (connect_res < 0) {
            sc_g_log_function("ERR: tls connection failed: %d", connect_res);
            close(sock_fd);
            free(sock);
            return NULL;
        }
    }

	return sock; 
}

// return of <= 0 == failure
int
socket_wait(sc_socket* sock, int timeout_ms, bool read, short* poll_res)
{
	int rv;
    short events = POLLOUT;

    if (read) {
        events = POLLIN;
    }

    struct pollfd pfd = {
        .fd = sock->fd,
        .events = events
    };

    rv = poll(&pfd, 1, (int)timeout_ms);

	if (rv == 0) {
		sc_g_log_function("ERR: socket poll timed out");
		return rv;
	}
	else if (rv < 0) {
		sc_g_log_function("ERR: socket poll err: %d, errno: %d", rv, errno);
		return rv;
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
        rv = -1;
    }

    return rv;
}

sc_tls_cfg*
sc_tls_cfg_init(sc_tls_cfg* cfg) {
    cfg->ca_string = NULL;
    cfg->enabled = false;
    return cfg;
}

sc_tls_cfg*
sc_tls_cfg_new() {
    sc_tls_cfg* cfg = (sc_tls_cfg*) malloc(sizeof(sc_tls_cfg));
    sc_tls_cfg_init(cfg);
    return cfg;
}

//==========================================================
// Private Helpers.
//

int _read_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
    int bytes_read = 0;
    int result = 0;
    short poll_res = 0;
    while (true)
    {
        result = socket_wait(sock, timeout_ms, true, &poll_res);
        if (result <= 0) {
            sc_g_log_function("ERR: socket poll failed on read, return value: %d, revent: %d, errno: %d", result, poll_res, errno);
            return result;
        }

        result = read(sock->fd, buffer + bytes_read, n - bytes_read);
        if (result < 0 ) {
            sc_g_log_function("ERR: socket read failed, return value: %d, errno: %d", result, errno);
            return result;
        }

        if (result == 0) {
            // end of transmission
            return result;
        }

        bytes_read += result;
        if (bytes_read >= n) {
            return result;
        }
    }
}

int _write_n_bytes(sc_socket* sock, unsigned int n, void* buffer, int timeout_ms)
{
    int bytes_written = 0;
    int result = 0;
    short poll_res = 0;
    while (true)
    {
        result = socket_wait(sock, timeout_ms, false, &poll_res);
        if (result <= 0) {
            sc_g_log_function("ERR: socket poll failed on write, return value: %d, revent: %d, errno: %d", result, poll_res, errno);
            return result;
        }

        result = write(sock->fd, buffer + bytes_written, n - bytes_written);
        if (result < 0 )
        {
            sc_g_log_function("ERR: socket write failed, return value: %d, errno: %d", result, errno);
            return result;
        }

        bytes_written += result;
        if (bytes_written >= n) {
            return result;
        }
    }
}

// return != 0 == failure
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